// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"alloyium.local/kernel-poc/internal/control"
	"alloyium.local/kernel-poc/internal/localconfig"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("Community command failed", "error", err.Error())
		os.Exit(1)
	}
}
func location(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
func jsonFile(name string, dest any) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	return boundedJSON(f, dest)
}
func boundedJSON(r io.Reader, dest any) error {
	data, err := io.ReadAll(io.LimitReader(r, 65537))
	if err != nil || len(data) > 65536 {
		return errors.New("JSON input exceeds the limit")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(dest); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("supply one JSON object")
	}
	return nil
}
func exclusive(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, "community.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("one Community command must own this state")
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}
func run(args []string) error {
	state := location("AGENTGATE_STATE_DIR", "/var/lib/agentgate")
	trust := location("AGENTGATE_TRUST_DIR", "/var/lib/agentgate-trust/instance")
	if !filepath.IsAbs(state) || !filepath.IsAbs(trust) {
		return errors.New("absolute state and trust paths required")
	}
	if len(args) > 0 && args[0] == "openapi" {
		value, err := control.CommunityOpenAPI()
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(value)
	}
	if len(args) == 3 && args[0] == "restore" {
		return restore(args[1], args[2], trust)
	}
	if err := os.MkdirAll(state, 0700); err != nil {
		return err
	}
	unlock, err := exclusive(state)
	if err != nil {
		return err
	}
	defer unlock()
	configDir := filepath.Join(state, "config")
	if len(args) == 2 && args[0] == "init" {
		var settings localconfig.Settings
		if err = jsonFile(args[1], &settings); err != nil {
			return err
		}
		config, err := localconfig.New(configDir, trust, settings)
		if err != nil {
			return err
		}
		defer config.DB.Close()
		record, err := config.Read()
		if err != nil {
			return err
		}
		store, err := control.OpenStore(filepath.Join(state, "data"))
		if err != nil {
			return err
		}
		defer store.DB.Close()
		if err = config.PinAuthority(control.EncodePublic(store.Authority.Public().(ed25519.PublicKey))); err != nil {
			return err
		}
		if err = config.PinJobKey(store.JobPublicKey(), false); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"result": "initialized", "instance": record.Instance, "revision": record.Revision})
	}
	config, err := localconfig.Open(configDir, trust)
	if err != nil {
		return err
	}
	defer config.DB.Close()
	record, err := config.Read()
	if err != nil {
		return err
	}
	if len(args) > 0 && args[0] == "config" {
		if len(args) != 4 {
			return errors.New("config requires settings JSON, parent revision and reason")
		}
		var settings localconfig.Settings
		if err = jsonFile(args[1], &settings); err != nil {
			return err
		}
		parent, err := strconv.ParseInt(args[2], 10, 64)
		if err != nil {
			return err
		}
		next, err := config.Publish(localconfig.Operation{Actor: "deployment-administrator", Kind: "system", RequestID: strconv.FormatInt(time.Now().UnixNano(), 10), Reason: args[3]}, settings, parent)
		if err != nil {
			return err
		}
		if _, err = config.Read(); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(next)
	}
	spool := filepath.Join(state, "data", "spool")
	if err = os.MkdirAll(spool, 0700); err != nil {
		return err
	}
	if err = os.Setenv("TMPDIR", spool); err != nil {
		return err
	}
	store, err := control.OpenStore(filepath.Join(state, "data"))
	if err != nil {
		return err
	}
	defer store.DB.Close()
	if err = config.VerifyAuthority(control.EncodePublic(store.Authority.Public().(ed25519.PublicKey))); err != nil {
		return err
	}
	if len(args) == 2 && args[0] == "rotate-job-key" {
		public, err := store.RotateJobKey(filepath.Join(state, "data"), args[1])
		if err != nil {
			return err
		}
		if err = config.PinJobKey(public, true); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"result": "rotated", "job_key": public, "job_key_id": store.JobKeyID(), "next": "issue a new enrollment token for every target and enroll each host again"})
	}
	if err = config.VerifyJobKey(store.JobPublicKey()); errors.Is(err, os.ErrNotExist) {
		// A deployment created before host job keys pins its first job key now.
		if err = config.PinJobKey(store.JobPublicKey(), false); err != nil {
			return err
		}
		slog.Info("Pinned the host job key", "job_key_id", store.JobKeyID())
	} else if err != nil {
		return fmt.Errorf("%w; run rotate-job-key to re-pin after a restore without a job key", err)
	}
	store.LocalIdentity = true
	store.CustomerPolicy = true
	if len(args) == 1 && args[0] == "first-admin" {
		if !record.Settings.LocalEnabled() {
			return errors.New("local authentication is disabled")
		}
		var in struct {
			Username string `json:"username"`
			Name     string `json:"name"`
			Password string `json:"password"`
		}
		if err = boundedJSON(os.Stdin, &in); err != nil {
			return err
		}
		if err = store.BootstrapAdmin(in.Username, in.Name, in.Password); err != nil {
			return err
		}
		fmt.Println("FIRST_ADMIN_READY")
		return nil
	}
	if len(args) == 2 && args[0] == "enroll" {
		var svc control.Service
		if err = jsonFile(args[1], &svc); err != nil {
			return err
		}
		_, err = store.RegisterService(control.Operation{Actor: control.Actor{Subject: "deployment-administrator", Kind: "system", Scopes: []string{"agents:write"}}, RequestID: strconv.FormatInt(time.Now().UnixNano(), 10)}, svc)
		return err
	}
	if len(args) == 2 && args[0] == "backup" {
		return backup(config, store, record, args[1])
	}
	if len(args) == 1 && args[0] == "public-key" {
		fmt.Println(control.EncodePublic(store.Authority.Public().(ed25519.PublicKey)))
		return nil
	}
	if len(args) == 1 && args[0] == "job-key" {
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"job_key": store.JobPublicKey(), "job_key_id": store.JobKeyID()})
	}
	if len(args) != 0 && !(len(args) == 1 && args[0] == "serve") {
		return errors.New("use init, first-admin, config, enroll, public-key, job-key, rotate-job-key, backup, restore or serve")
	}
	if record.Settings.LocalEnabled() {
		users, err := store.Users()
		if err != nil {
			return err
		}
		ready := false
		for _, user := range users {
			if user.Enabled {
				for _, role := range user.Roles {
					if role == "admin" {
						ready = true
					}
				}
			}
		}
		if !ready {
			return errors.New("enroll the first local administrator before startup")
		}
	}
	cfg := control.CommunityAuthConfig(record.Settings, record.Instance)
	if record.Settings.OIDCEnabled() {
		name := os.Getenv("OIDC_CLIENT_SECRET_FILE")
		info, err := os.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("a private regular OIDC client secret file is required")
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		cfg.ClientSecret = strings.TrimSpace(string(data))
		if cfg.ClientSecret == "" || len(cfg.ClientSecret) > 4096 {
			return errors.New("OIDC client secret is empty or too large")
		}
	}
	return serve(store, config, record, cfg, spool)
}
func serve(store *control.Store, config *localconfig.Store, record localconfig.Record, cfg control.AuthConfig, spool string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	auth, err := control.NewAuth(ctx, store, cfg)
	cancel()
	if err != nil {
		return errors.New("identity provider initialization failed")
	}
	auth.BindCommunityConfig(config, record)
	app := control.NewServer(store, auth, spool, location("AGENTGATE_WEB_DIR", "/opt/agentgate/web"))
	if err = control.CheckWeb(app.Web); err != nil {
		return err
	}
	server := &http.Server{Addr: record.Settings.Listen, Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	closed := make(chan os.Signal, 1)
	signal.Notify(closed, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(closed)
	sweep, stopSweep := context.WithCancel(context.Background())
	defer stopSweep()
	go store.RunSweeper(sweep, 0)
	go func() {
		<-closed
		stopSweep()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()
	slog.Info("Community ready", "listen", server.Addr, "instance", record.Instance)
	err = server.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
