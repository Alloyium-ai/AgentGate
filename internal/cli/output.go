// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"
)

// printer writes command results. Human output goes to standard output;
// notes and progress go to standard error; --json prints exactly one JSON
// value on standard output with the API's field names.
type printer struct {
	out, err io.Writer
	json     bool
	quiet    bool
	color    bool
}

const (
	colorReset  = "\x1b[0m"
	colorRed    = "\x1b[31m"
	colorGreen  = "\x1b[32m"
	colorYellow = "\x1b[33m"
	colorBold   = "\x1b[1m"
)

func (p *printer) paint(code, s string) string {
	if !p.color || s == "" {
		return s
	}
	return code + s + colorReset
}

// state colors a launch or target state.
func (p *printer) state(s string) string {
	switch s {
	case "running", "active", "stopped", "stored":
		return p.paint(colorGreen, s)
	case "approval_pending", "awaiting_key_approval", "pending", "queued", "provisioning", "stopping", "approved", "requested", "deleting", "rekey_required":
		return p.paint(colorYellow, s)
	case "failed", "rejected", "cancelled", "expired", "retired", "deleted":
		return p.paint(colorRed, s)
	}
	return s
}

// note writes an informational line to standard error unless --quiet.
func (p *printer) note(format string, args ...any) {
	if p.quiet {
		return
	}
	fmt.Fprintf(p.err, format+"\n", args...)
}

// warn always writes to standard error.
func (p *printer) warn(format string, args ...any) {
	fmt.Fprintf(p.err, p.paint(colorYellow, "warning:")+" "+format+"\n", args...)
}

// line writes one line of human output to standard output.
func (p *printer) line(format string, args ...any) {
	fmt.Fprintf(p.out, format+"\n", args...)
}

// table writes aligned columns. Cell text is cleaned of control characters
// so a service value cannot move the cursor or recolor the terminal.
func (p *printer) table(header []string, rows [][]string) {
	tw := tabwriter.NewWriter(p.out, 0, 0, 2, ' ', 0)
	if len(header) > 0 {
		fmt.Fprintln(tw, strings.Join(header, "\t"))
	}
	for _, row := range rows {
		cells := make([]string, len(row))
		for i, c := range row {
			cells[i] = clean(c)
			if cells[i] == "" {
				cells[i] = "-"
			}
		}
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	tw.Flush()
}

// fields writes "label  value" pairs.
func (p *printer) fields(indent string, pairs [][2]string) {
	tw := tabwriter.NewWriter(p.out, 0, 0, 2, ' ', 0)
	for _, kv := range pairs {
		v := clean(kv[1])
		if strings.TrimSpace(v) == "" {
			v = "-"
		}
		fmt.Fprintf(tw, "%s%s\t%s\n", indent, kv[0], v)
	}
	tw.Flush()
}

// rawJSON prints a JSON document indented.
func (p *printer) rawJSON(raw []byte) error {
	var buf bytes.Buffer
	if err := json.Indent(&buf, bytes.TrimSpace(raw), "", "  "); err != nil {
		return &Error{Exit: ExitServer, Code: "invalid_response", Message: "The service answered with invalid JSON."}
	}
	buf.WriteByte('\n')
	_, err := p.out.Write(buf.Bytes())
	return err
}

// value prints a Go value as indented JSON.
func (p *printer) value(v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = p.out.Write(append(raw, '\n'))
	return err
}

// clean drops control characters (including escape sequences) from text the
// service supplied.
func clean(s string) string {
	if strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) && r != ' ' }) < 0 {
		return s
	}
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

func joinOr(values []string, empty string) string {
	if len(values) == 0 {
		return empty
	}
	return strings.Join(values, ", ")
}

// age shows a timestamp relative to now, for tables.
func age(stamp string, now time.Time) string {
	t, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil {
		return stamp
	}
	d := now.Sub(t)
	future := d < 0
	if future {
		d = -d
	}
	var s string
	switch {
	case d < time.Minute:
		s = fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		s = fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		s = fmt.Sprintf("%dh", int(d.Hours()))
	default:
		s = fmt.Sprintf("%dd", int(d.Hours()/24))
	}
	if future {
		return "in " + s
	}
	return s + " ago"
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func shortDigest(d string) string {
	if len(d) > 16 {
		return d[:16]
	}
	return d
}

// quoteArgs shows a command line unambiguously.
func quoteArgs(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if a == "" || strings.ContainsAny(a, " \t\n\"'\\$`;&|<>(){}*?!#~") {
			out[i] = fmt.Sprintf("%q", a)
		} else {
			out[i] = a
		}
	}
	return strings.Join(out, " ")
}

func humanSeconds(n int) string {
	d := time.Duration(n) * time.Second
	switch {
	case n%3600 == 0:
		return fmt.Sprintf("%dh", n/3600)
	case n%60 == 0 && n >= 60:
		return fmt.Sprintf("%dm", n/60)
	}
	return d.String()
}
