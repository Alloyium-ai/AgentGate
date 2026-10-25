// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

const maxDocumentBytes = 16 << 10

func init() {
	register(&command{name: "profile ls", summary: "List access profiles.", setup: func(fs *flag.FlagSet) runner {
		return func(ctx context.Context, e *env, args, _ []string) error { return e.profileList(ctx) }
	}})
	register(&command{name: "profile show", args: "NAME", summary: "Show a profile and the policy of one version (default: the latest).",
		help: "  --version N   show this version", setup: func(fs *flag.FlagSet) runner {
			version := fs.Int("version", 0, "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) != 1 {
					return usageError("profile show takes one profile name")
				}
				return e.profileShow(ctx, args[0], *version)
			}
		}})
	register(&command{name: "profile new", args: "NAME", summary: "Create a profile from a preset, a policy document, or the full example.",
		help: `  --preset NAME       start from a preset (agentgate preset ls)
  --file FILE|-       start from an agentgate.poc.v2 policy document
  --description TEXT
  --no-approval       launches of this profile skip approval when nothing else requires it (admin only)
  --reason TEXT`,
		setup: func(fs *flag.FlagSet) runner {
			preset := fs.String("preset", "", "")
			file := fs.String("file", "", "")
			description := fs.String("description", "", "")
			noApproval := fs.Bool("no-approval", false, "")
			reason := fs.String("reason", "", "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) != 1 {
					return usageError("profile new takes one profile name")
				}
				return e.profileNew(ctx, args[0], *preset, *file, *description, *noApproval, *reason)
			}
		}})
	register(&command{name: "profile versions", args: "NAME", summary: "List the immutable versions of a profile.", setup: func(fs *flag.FlagSet) runner {
		return func(ctx context.Context, e *env, args, _ []string) error {
			if len(args) != 1 {
				return usageError("profile versions takes one profile name")
			}
			return e.profileVersions(ctx, args[0])
		}
	}})
	register(&command{name: "profile approval", args: "NAME required|auto", summary: "Set whether launches of a profile need a second human (admin).",
		help: `  --version N   with auto (required): the one version you reviewed; launchers may start only that
                version alone, every other version (a newer one too) needs a second human
  --reason TEXT
auto prints the version's digest and sends it, so a version that differs from the one you looked at is refused.`, setup: func(fs *flag.FlagSet) runner {
			reason := fs.String("reason", "", "")
			version := fs.Int("version", 0, "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) != 2 || (args[1] != "required" && args[1] != "auto") {
					return usageError("profile approval takes a profile name and required or auto")
				}
				if args[1] == "auto" && *version < 1 {
					return usageError("profile approval NAME auto approves one reviewed version: pass --version N (agentgate profile show NAME --version N shows it)")
				}
				if args[1] == "required" && *version != 0 {
					return usageError("--version goes with auto only")
				}
				return e.profileApproval(ctx, args[0], args[1] == "required", *version, *reason)
			}
		}})
	register(&command{name: "preset ls", summary: "List access presets and the grant actions.", setup: func(fs *flag.FlagSet) runner {
		return func(ctx context.Context, e *env, args, _ []string) error { return e.presetList(ctx) }
	}})
	register(&command{name: "grant", args: "PROFILE ACTION [VALUE...]", summary: "Change a profile's access with one typed edit; the service stores a new version.",
		help: `Actions:
  read|write|exec|deny PATH       grant read-only, writable, executable or denied access to a tree
  web [allow|deny] [PROTO...]     allow or deny public web protocols (http, https, quic, all)
  dns IP [IP [IP]]                set 1 to 3 public IPv4 resolvers
  signal SIG...                   allow signals within the agent's own process tree (TERM, INT, ...)
  anon-exec                       allow executable anonymous memory (JITs)
  mount NAME [--mode read-only|read-write]   allow the agent to use a spec mount NAME
  unmount NAME
  preset NAME                     merge a preset
  device DEVICE                   allow /dev/null, /dev/zero, /dev/full, /dev/random, /dev/urandom or /dev/tty
  revoke KIND [VALUE...]          remove a grant (KIND: web dns read write exec deny signal anon-exec mount device)
Flags:
  --mode MODE     mount access mode (default read-only)
  --upgrade       allow upgrading a version one profile to version two
  --reason TEXT   audit reason (default: a description of the edit)
  --dry-run       the service computes the change and its diff; nothing is stored
The edit always applies to the latest version; the CLI never edits the policy document itself.`,
		setup: func(fs *flag.FlagSet) runner {
			mode := fs.String("mode", "read-only", "")
			upgrade := fs.Bool("upgrade", false, "")
			reason := fs.String("reason", "", "")
			dryRun := fs.Bool("dry-run", false, "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) < 2 {
					return usageError("grant takes a profile name, an action and its values (agentgate grant --help)")
				}
				edit, err := parseGrant(args[1], args[2:], *mode, *upgrade)
				if err != nil {
					return err
				}
				return e.grant(ctx, args[0], edit, *reason, *dryRun)
			}
		}})
}

// parseGrant maps the grant command line to one typed edit.
func parseGrant(action string, values []string, mode string, upgrade bool) (GrantEdit, error) {
	edit := GrantEdit{Action: action, Values: values, UpgradeToV2: upgrade}
	need := func(min, max int, what string) error {
		if len(values) < min || (max >= 0 && len(values) > max) {
			return usageError("grant %s takes %s", action, what)
		}
		return nil
	}
	var err error
	switch action {
	case "read", "write", "exec", "deny":
		err = need(1, 1, "one absolute path")
	case "web":
		edit.Action = "allow-web"
		if len(values) > 0 && (values[0] == "allow" || values[0] == "deny") {
			if values[0] == "deny" {
				edit.Action = "deny-web"
			}
			edit.Values = values[1:]
		}
	case "allow-web", "deny-web":
	case "dns":
		err = need(1, 3, "1 to 3 public IPv4 resolver addresses")
	case "signal":
		err = need(1, -1, "one or more signal names")
	case "anon-exec":
		err = need(0, 0, "no values")
	case "mount":
		if err = need(1, 1, "one mount name"); err == nil {
			if mode != "read-only" && mode != "read-write" {
				err = usageError("--mode is read-only or read-write")
			}
			edit.Mode = mode
		}
	case "unmount":
		err = need(1, 1, "one mount name")
	case "device":
		err = need(1, 1, "one device: /dev/null, /dev/zero, /dev/full, /dev/random, /dev/urandom or /dev/tty")
	case "preset":
		err = need(1, 1, "one preset name")
	case "revoke":
		if len(values) < 1 {
			return edit, usageError("grant revoke takes a kind (%s) and its values", strings.Join(grantRevokeKinds, ", "))
		}
		edit.Kind, edit.Values = values[0], values[1:]
	default:
		return edit, usageError("unknown grant action %q (read, write, exec, deny, web, dns, signal, anon-exec, mount, unmount, device, preset, revoke)", action)
	}
	if len(edit.Values) == 0 {
		edit.Values = nil
	}
	if len(edit.Values) > maxGrantValues {
		return edit, usageError("at most %d values per edit", maxGrantValues)
	}
	return edit, err
}

func describeEdit(edit GrantEdit) string {
	parts := []string{edit.Action}
	if edit.Kind != "" {
		parts = append(parts, edit.Kind)
	}
	parts = append(parts, edit.Values...)
	if edit.Mode != "" {
		parts = append(parts, edit.Mode)
	}
	s := strings.Join(parts, " ")
	if len(s) > 480 {
		s = s[:480]
	}
	return s
}

func (e *env) profileList(ctx context.Context) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	var list items[Profile]
	raw, err := c.get(ctx, apiPrefix+"/profiles", nil, &list)
	if err != nil {
		return err
	}
	return e.emit(raw, func() error {
		if e.g.quiet {
			for _, p := range list.Items {
				e.p.line("%s", p.Name)
			}
			return nil
		}
		rows := [][]string{}
		for _, p := range list.Items {
			approval := "required"
			if !p.RequireApproval && p.ApprovedVersion > 0 {
				approval = "auto v" + strconv.Itoa(p.ApprovedVersion)
			}
			rows = append(rows, []string{p.Name, strconv.Itoa(p.LatestVersion), approval, p.CreatedBy, p.Description})
		}
		e.p.table([]string{"NAME", "LATEST", "APPROVAL", "CREATED BY", "DESCRIPTION"}, rows)
		return nil
	})
}

func (e *env) getProfile(ctx context.Context, c *Client, ref string) (Profile, error) {
	var p Profile
	_, err := c.get(ctx, apiPrefix+"/profiles/"+pathEscape(ref), nil, &p)
	return p, err
}

func (e *env) getVersion(ctx context.Context, c *Client, ref string, n int) (ProfileVersion, []byte, error) {
	var v ProfileVersion
	raw, err := c.get(ctx, apiPrefix+"/profiles/"+pathEscape(ref)+"/versions/"+strconv.Itoa(n), nil, &v)
	return v, raw, err
}

func (e *env) profileShow(ctx context.Context, ref string, n int) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	p, err := e.getProfile(ctx, c, ref)
	if err != nil {
		return err
	}
	if n == 0 {
		n = p.LatestVersion
	}
	v, _, err := e.getVersion(ctx, c, p.ID, n)
	if err != nil {
		return err
	}
	if e.g.json {
		return e.p.value(map[string]any{"profile": p, "version": v})
	}
	approval := "required for every launch"
	switch {
	case !p.RequireApproval && p.ApprovedVersion > 0:
		approval = fmt.Sprintf("not required for version %d (digest %s, approved by %s); every other version needs approval (other reasons may still require it)", p.ApprovedVersion, shortDigest(p.ApprovedDigest), p.ApprovedBy)
	case !p.RequireApproval:
		approval = "required: no version is approved for launches without approval"
	}
	e.p.fields("", [][2]string{{"name", p.Name}, {"id", p.ID}, {"description", p.Description}, {"approval", approval},
		{"version", fmt.Sprintf("%d of %d", v.Number, p.LatestVersion)}, {"digest", v.Digest}, {"changed by", v.Actor}, {"reason", v.Reason}, {"created", v.Created}})
	e.p.line("\npolicy:")
	for _, l := range flatten(v.Document) {
		e.p.line("  %s", clean(l))
	}
	return nil
}

func readDocument(path string, stdin func() ([]byte, error)) (json.RawMessage, error) {
	var raw []byte
	var err error
	if path == "-" {
		raw, err = stdin()
	} else {
		raw, err = readBounded(path, maxDocumentBytes)
	}
	if err != nil {
		return nil, usageError("cannot read %s: %v", path, err)
	}
	if len(raw) > maxDocumentBytes {
		return nil, usageError("%s exceeds %d bytes", path, maxDocumentBytes)
	}
	raw = bytes.TrimSpace(raw)
	if !json.Valid(raw) || len(raw) == 0 || raw[0] != '{' {
		return nil, usageError("%s is not one JSON object", path)
	}
	return raw, nil
}

func (e *env) readAllStdin(max int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(e.stdin(), max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > max {
		return nil, fmt.Errorf("standard input exceeds %d bytes", max)
	}
	return raw, nil
}

func (e *env) profileNew(ctx context.Context, name, preset, file, description string, noApproval bool, reason string) error {
	if preset != "" && file != "" {
		return usageError("choose --preset or --file, not both")
	}
	c, err := e.authed()
	if err != nil {
		return err
	}
	if reason, err = defaultReason(reason, "Create profile "+name+" with the agentgate CLI"); err != nil {
		return err
	}
	body := map[string]any{"name": name, "reason": reason}
	if description != "" {
		body["description"] = description
	}
	if preset != "" {
		body["preset"] = preset
	}
	if file != "" {
		doc, err := readDocument(file, func() ([]byte, error) { return e.readAllStdin(maxDocumentBytes) })
		if err != nil {
			return err
		}
		body["document"] = doc
	}
	if noApproval {
		body["require_approval"] = false
	}
	var out struct {
		Profile Profile        `json:"profile"`
		Version ProfileVersion `json:"version"`
	}
	raw, err := c.mutate(ctx, "POST", apiPrefix+"/profiles", body, true, &out)
	if err != nil {
		return err
	}
	return e.emit(raw, func() error {
		approval := "need approval by a second human"
		if !out.Profile.RequireApproval {
			approval = "of this version skip approval unless the plan requires it (later versions need approval until an administrator approves one)"
		}
		e.p.line("Created profile %s (version %d, digest %s); its launches %s.", out.Profile.Name, out.Version.Number, shortDigest(out.Version.Digest), approval)
		e.p.note("Grant access with agentgate grant %s read|write|exec|web|... (agentgate grant --help).", out.Profile.Name)
		return nil
	})
}

func (e *env) profileVersions(ctx context.Context, ref string) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	var list items[ProfileVersion]
	raw, err := c.get(ctx, apiPrefix+"/profiles/"+pathEscape(ref)+"/versions", nil, &list)
	if err != nil {
		return err
	}
	return e.emit(raw, func() error {
		if e.g.quiet {
			for _, v := range list.Items {
				e.p.line("%d", v.Number)
			}
			return nil
		}
		rows := [][]string{}
		for _, v := range list.Items {
			var edits []GrantEdit
			json.Unmarshal(v.Edits, &edits)
			desc := []string{}
			for _, ed := range edits {
				desc = append(desc, describeEdit(ed))
			}
			rows = append(rows, []string{strconv.Itoa(v.Number), shortDigest(v.Digest), v.Actor, v.Created, strings.Join(desc, "; "), v.Reason})
		}
		e.p.table([]string{"VERSION", "DIGEST", "ACTOR", "CREATED", "EDITS", "REASON"}, rows)
		return nil
	})
}

func (e *env) profileApproval(ctx context.Context, ref string, required bool, version int, reason string) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	word := map[bool]string{true: "required", false: "auto"}[required]
	if reason, err = defaultReason(reason, "Set launch approval of profile "+ref+" to "+word); err != nil {
		return err
	}
	body := map[string]any{"require_approval": required, "reason": reason}
	if !required {
		pr, err := e.getProfile(ctx, c, ref)
		if err != nil {
			return err
		}
		v, _, err := e.getVersion(ctx, c, pr.ID, version)
		if err != nil {
			return err
		}
		if !e.g.json {
			e.p.line("Approving profile %s version %d (digest %s) for launches without a second human.", pr.Name, v.Number, v.Digest)
			e.p.note("Every other version of the profile, including newer ones, still needs approval.")
		}
		body["version"], body["digest"] = v.Number, v.Digest
	}
	var p Profile
	raw, err := c.mutate(ctx, "PATCH", apiPrefix+"/profiles/"+pathEscape(ref), body, true, &p)
	if err != nil {
		return err
	}
	return e.emit(raw, func() error {
		if required {
			e.p.line("Profile %s: launch approval required.", p.Name)
		} else {
			e.p.line("Profile %s: launches of version %d (digest %s) start without approval; other versions need it.", p.Name, p.ApprovedVersion, shortDigest(p.ApprovedDigest))
		}
		return nil
	})
}

func (e *env) presetList(ctx context.Context) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	var list PresetList
	raw, err := c.get(ctx, apiPrefix+"/access-presets", nil, &list)
	if err != nil {
		return err
	}
	return e.emit(raw, func() error {
		if e.g.quiet {
			for _, p := range list.Items {
				e.p.line("%s", p.Name)
			}
			return nil
		}
		rows := [][]string{}
		for _, p := range list.Items {
			rows = append(rows, []string{p.Name, joinOr(p.Web, "none"), p.Description})
		}
		e.p.table([]string{"PRESET", "WEB", "DESCRIPTION"}, rows)
		e.p.line("\ngrant actions: %s", strings.Join(list.Actions, ", "))
		e.p.line("revoke kinds:  %s", strings.Join(list.RevokeKinds, ", "))
		return nil
	})
}

// grantOutcome is the --json form of a grant or its preview.
type grantOutcome struct {
	DryRun      bool            `json:"dry_run"`
	Profile     string          `json:"profile"`
	FromVersion int             `json:"from_version"`
	FromDigest  string          `json:"from_digest"`
	Digest      string          `json:"digest"`
	Changed     bool            `json:"changed"`
	Version     *ProfileVersion `json:"version,omitempty"`
	Changes     []PolicyChange  `json:"changes"`
	Added       []string        `json:"added"`
	Removed     []string        `json:"removed"`
	Messages    []string        `json:"messages"`
	Notices     []string        `json:"notices"`
	Preview     string          `json:"preview,omitempty"`
}

func (e *env) grant(ctx context.Context, ref string, edit GrantEdit, reason string, dryRun bool) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	p, err := e.getProfile(ctx, c, ref)
	if err != nil {
		return err
	}
	parent, _, err := e.getVersion(ctx, c, p.ID, p.LatestVersion)
	if err != nil {
		return err
	}
	out := grantOutcome{DryRun: dryRun, Profile: p.Name, FromVersion: parent.Number, Messages: []string{}, Notices: []string{}, Changes: []PolicyChange{}}
	defaultText := "agentgate grant " + describeEdit(edit)
	if dryRun {
		defaultText = "Preview agentgate grant " + describeEdit(edit)
	}
	if reason, err = defaultReason(reason, defaultText); err != nil {
		return err
	}
	body := map[string]any{"edits": []GrantEdit{edit}, "reason": reason}
	if dryRun {
		// The service runs the grant with every check and stores nothing.
		body["dry_run"] = true
	}
	var res GrantResult
	path := apiPrefix + "/profiles/" + pathEscape(p.ID) + "/versions/" + strconv.Itoa(parent.Number) + "/grants"
	if _, err = c.mutate(ctx, "POST", path, body, true, &res); err != nil {
		return err
	}
	after := res.Version.Document
	if dryRun {
		if !res.DryRun || len(res.Document) == 0 {
			return &Error{Exit: ExitServer, Code: "invalid_response", Message: "The service did not answer the grant as a dry run; nothing is shown as a preview.", Hint: "Upgrade the service; the CLI never simulates a grant itself."}
		}
		after = res.Document
		out.Preview = "computed by the service on version " + strconv.Itoa(parent.Number) + "; nothing was stored"
	} else {
		out.Version = &res.Version
	}
	out.Changed, out.FromDigest, out.Digest = res.Changed, res.FromDigest, res.Digest
	out.Messages, out.Notices = append(out.Messages, res.Messages...), append(out.Notices, res.Notices...)
	if res.Changes != nil {
		out.Changes = res.Changes
	}
	out.Added, out.Removed = diffDocuments(parent.Document, after)
	if e.g.json {
		return e.p.value(out)
	}
	switch {
	case dryRun && out.Changed:
		e.p.line("Preview for profile %s: version %d -> %d would store digest %s (nothing was stored):", p.Name, parent.Number, parent.Number+1, shortDigest(out.Digest))
	case dryRun:
		e.p.line("Preview for profile %s, version %d: no change, nothing would be stored (nothing was stored).", p.Name, parent.Number)
	case out.Changed:
		e.p.line("Profile %s: version %d -> %d (digest %s).", p.Name, parent.Number, out.Version.Number, shortDigest(out.Version.Digest))
	default:
		e.p.line("Profile %s: no change; version %d already allows this.", p.Name, parent.Number)
	}
	for _, l := range out.Removed {
		e.p.line("  %s %s", e.p.paint(colorRed, "-"), clean(l))
	}
	for _, l := range out.Added {
		e.p.line("  %s %s", e.p.paint(colorGreen, "+"), clean(l))
	}
	for _, m := range out.Messages {
		if m != "" {
			e.p.line("%s", clean(m))
		}
	}
	for _, n := range out.Notices {
		e.p.line("notice: %s", clean(n))
	}
	if dryRun {
		e.p.note("The service checked this edit and stored nothing; run it without --dry-run to store a new version.")
	}
	return nil
}

// flatten renders a JSON document as sorted "path = value" lines; array
// elements become "path[] value", so a diff shows added and removed entries.
func flatten(raw json.RawMessage) []string {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&v) != nil {
		return nil
	}
	out := []string{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch t := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				walk(p, t[k])
			}
		case []any:
			if len(t) == 0 {
				out = append(out, prefix+" = []")
			}
			for _, item := range t {
				switch item.(type) {
				case map[string]any, []any:
					compact, _ := json.Marshal(item)
					out = append(out, prefix+"[] "+string(compact))
				default:
					out = append(out, prefix+"[] "+scalar(item))
				}
			}
		default:
			out = append(out, prefix+" = "+scalar(t))
		}
	}
	walk("", v)
	sort.Strings(out)
	return out
}

func scalar(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return "null"
	}
	return fmt.Sprint(v)
}

func diffDocuments(before, after json.RawMessage) (added, removed []string) {
	a, b := map[string]int{}, map[string]int{}
	for _, l := range flatten(before) {
		a[l]++
	}
	for _, l := range flatten(after) {
		b[l]++
	}
	added, removed = []string{}, []string{}
	for l, n := range b {
		for i := a[l]; i < n; i++ {
			added = append(added, l)
		}
	}
	for l, n := range a {
		for i := b[l]; i < n; i++ {
			removed = append(removed, l)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}
