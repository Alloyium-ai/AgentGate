// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
)

// The walkthroughs are meant to be pasted. Every agentgate command in a shell
// block of the POC README quickstart and of docs/CLI.md must name a command
// that exists and parse with that command's flags.

// shellWords splits one shell command line: quotes, a trailing comment, an
// input redirection and the $( ) of a command substitution are handled; the
// commands in the docs need nothing more.
func shellWords(line string) []string {
	var out []string
	var cur strings.Builder
	in, started := byte(0), false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case in != 0:
			if c == in {
				in = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '\'' || c == '"':
			in, started = c, true
		case c == '#' && !started:
			i = len(line)
		case c == ' ' || c == '\t':
			if started {
				out = append(out, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteByte(c)
			started = true
		}
	}
	if started {
		out = append(out, cur.String())
	}
	// Drop an input redirection and what follows it.
	for i, w := range out {
		if w == "<" {
			return out[:i]
		}
	}
	return out
}

var agentgateCommand = regexp.MustCompile(`(?:^|\$\(|&& |; )agentgate (.*)$`)

func docCommands(t *testing.T, path string, from, to string) [][]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("%s: %v", path, err)
	}
	text := string(raw)
	if from != "" {
		start := strings.Index(text, from)
		if start < 0 {
			t.Fatalf("%s has no %q", path, from)
		}
		text = text[start:]
		if end := strings.Index(text[len(from):], to); end >= 0 {
			text = text[:len(from)+end]
		}
	}
	var out [][]string
	inBlock := false
	pending := ""
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "```") {
			inBlock = !inBlock && strings.TrimPrefix(line, "```") == "sh"
			continue
		}
		if !inBlock {
			continue
		}
		if strings.HasSuffix(line, "\\") {
			pending += strings.TrimSuffix(line, "\\") + " "
			continue
		}
		line, pending = pending+line, ""
		m := agentgateCommand.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		words := shellWords(m[1])
		if synopsis(words) {
			continue
		}
		if strings.Contains(line, "$(agentgate") && len(words) > 0 {
			last := words[len(words)-1]
			words[len(words)-1] = strings.TrimSuffix(last, ")")
		}
		out = append(out, words)
	}
	return out
}

// synopsis reports a usage line ([optional] and (a | b) notation), not a
// command to paste.
func synopsis(words []string) bool {
	for _, w := range words {
		if strings.HasPrefix(w, "[") || strings.HasPrefix(w, "(") {
			return true
		}
	}
	return false
}

func checkDocCommand(args []string) error {
	path, rest := splitCommand(args)
	c := lookup(path)
	if c == nil {
		return fmt.Errorf("agentgate %s: no such command", strings.Join(args, " "))
	}
	fs := flag.NewFlagSet(c.name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	(&globals{}).register(fs)
	c.setup(fs)
	if _, _, err := parseArgs(fs, rest); err != nil {
		return fmt.Errorf("agentgate %s: %v", strings.Join(args, " "), err)
	}
	return nil
}

func TestDocumentedCommandsParse(t *testing.T) {
	readme := docCommands(t, "../../poc/ssh-diagnostic/README.md", "## Quickstart: provision, grant, launch", "\n## ")
	if len(readme) < 20 {
		t.Fatalf("the README walkthrough has only %d agentgate commands", len(readme))
	}
	cliDoc := docCommands(t, "../../docs/CLI.md", "", "")
	if len(cliDoc) < 20 {
		t.Fatalf("docs/CLI.md has only %d agentgate commands", len(cliDoc))
	}
	for _, args := range append(readme, cliDoc...) {
		if err := checkDocCommand(args); err != nil {
			t.Error(err)
		}
	}
	// The checker itself refuses an unknown flag and an unknown command.
	if checkDocCommand([]string{"launch", "--no-such-flag"}) == nil || checkDocCommand([]string{"no-such-command"}) == nil {
		t.Fatal("the documentation check accepts an unknown flag or command")
	}
}
