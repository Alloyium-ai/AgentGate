// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

func init() {
	register(&command{name: "audit", args: "[catalog]", summary: "Show the audit trail (every grant, launch, approval and stop, with actor and digests).",
		help: `  --launch ID      only records of this launch
  --since T        RFC 3339 time or a duration such as 1h or 7d
  --until T        RFC 3339 time or a duration before now
  --actor SUBJECT  only this actor
  --action NAME    only this action (agentgate audit catalog lists them)
  --resource R     only this resource, for example target:ID
  --limit N        at most N records (default 50, at most 1000)`,
		setup: func(fs *flag.FlagSet) runner {
			launch := fs.String("launch", "", "")
			since := fs.String("since", "", "")
			until := fs.String("until", "", "")
			actor := fs.String("actor", "", "")
			action := fs.String("action", "", "")
			resource := fs.String("resource", "", "")
			limit := fs.Int("limit", 50, "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) == 1 && args[0] == "catalog" {
					return e.auditCatalog(ctx)
				}
				if len(args) != 0 {
					return usageError("audit takes no arguments (or: audit catalog)")
				}
				q := url.Values{}
				for k, v := range map[string]string{"run": *launch, "actor": *actor, "action": *action, "resource": *resource} {
					if v != "" {
						q.Set(k, v)
					}
				}
				for k, v := range map[string]string{"after": *since, "before": *until} {
					if v != "" {
						t, err := parseSince(v, e.app.Now())
						if err != nil {
							return err
						}
						q.Set(k, t)
					}
				}
				if *limit < 1 || *limit > 1000 {
					return usageError("--limit is 1 to 1000")
				}
				return e.audit(ctx, q, *limit)
			}
		}})
	register(&command{name: "schema launch-spec", summary: "Print the JSON Schema (draft 2020-12) of agentgate.launch.v1.", setup: func(fs *flag.FlagSet) runner {
		return func(ctx context.Context, e *env, args, _ []string) error {
			c, err := e.authed()
			if err != nil {
				return err
			}
			raw, err := c.get(ctx, apiPrefix+"/launch-spec-schema", nil, nil)
			if err != nil {
				return err
			}
			return e.p.rawJSON(raw)
		}
	}})
	register(&command{name: "completion", args: "bash|zsh|fish", summary: "Print a shell completion script.", setup: func(fs *flag.FlagSet) runner {
		return func(ctx context.Context, e *env, args, _ []string) error {
			if len(args) != 1 {
				return usageError("completion takes bash, zsh or fish")
			}
			script, err := completion(args[0])
			if err != nil {
				return err
			}
			_, err = fmt.Fprint(e.app.Stdout, script)
			return err
		}
	}})
}

func (e *env) audit(ctx context.Context, q url.Values, limit int) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	entries := []AuditEntry{}
	next := ""
	for len(entries) < limit {
		page := q
		page.Set("limit", strconv.Itoa(min(100, limit-len(entries))))
		if next != "" {
			page.Set("cursor", next)
		}
		var p AuditPage
		if _, err := c.get(ctx, apiPrefix+"/audit", page, &p); err != nil {
			return err
		}
		entries = append(entries, p.Items...)
		next = p.Next
		if next == "" || len(p.Items) == 0 {
			break
		}
	}
	if e.g.json {
		out := map[string]any{"items": entries}
		if next != "" {
			out["next_cursor"] = next
		}
		return e.p.value(out)
	}
	rows := [][]string{}
	for _, a := range entries {
		rows = append(rows, []string{a.Time, a.Actor, a.Action, a.Resource, a.Result, a.Reason})
	}
	e.p.table([]string{"TIME", "ACTOR", "ACTION", "RESOURCE", "RESULT", "REASON"}, rows)
	if next != "" {
		e.p.note("More records exist; raise --limit or narrow with --since.")
	}
	return nil
}

func (e *env) auditCatalog(ctx context.Context) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	var out items[map[string]any]
	raw, err := c.get(ctx, apiPrefix+"/audit-catalog", nil, &out)
	if err != nil {
		return err
	}
	return e.emit(raw, func() error {
		rows := [][]string{}
		for _, item := range out.Items {
			action, _ := item["action"].(string)
			desc, _ := item["description"].(string)
			if desc == "" {
				desc, _ = item["meaning"].(string)
			}
			rows = append(rows, []string{action, desc})
		}
		e.p.table([]string{"ACTION", "MEANING"}, rows)
		return nil
	})
}

// completion renders a completion script from the command registry.
func completion(shell string) (string, error) {
	grp := groups()
	top := []string{"help"}
	seen := map[string]bool{}
	for _, c := range registry {
		word := strings.SplitN(c.name, " ", 2)[0]
		if !seen[word] {
			seen[word] = true
			top = append(top, word)
		}
	}
	sort.Strings(top)
	globals := "--context --server --ca-file --pin-cert --insecure --json --quiet --no-color --verbose --yes --timeout --help"
	switch shell {
	case "bash":
		var b strings.Builder
		b.WriteString("# bash completion for agentgate: source <(agentgate completion bash)\n_agentgate() {\n  local cur=\"${COMP_WORDS[COMP_CWORD]}\" first=\"${COMP_WORDS[1]}\"\n  if [ \"$COMP_CWORD\" -eq 1 ]; then\n    COMPREPLY=($(compgen -W \"" + strings.Join(top, " ") + "\" -- \"$cur\")); return\n  fi\n  case \"$first\" in\n")
		names := make([]string, 0, len(grp))
		for g := range grp {
			names = append(names, g)
		}
		sort.Strings(names)
		for _, g := range names {
			fmt.Fprintf(&b, "    %s) if [ \"$COMP_CWORD\" -eq 2 ]; then COMPREPLY=($(compgen -W \"%s\" -- \"$cur\")); return; fi ;;\n", g, strings.Join(grp[g], " "))
		}
		b.WriteString("    completion) COMPREPLY=($(compgen -W \"bash zsh fish\" -- \"$cur\")); return ;;\n  esac\n  COMPREPLY=($(compgen -W \"" + globals + "\" -- \"$cur\"))\n}\ncomplete -F _agentgate agentgate\n")
		return b.String(), nil
	case "zsh":
		var b strings.Builder
		b.WriteString("#compdef agentgate\n# zsh completion for agentgate: agentgate completion zsh > \"${fpath[1]}/_agentgate\"\n_agentgate() {\n  if (( CURRENT == 2 )); then\n    compadd -- " + strings.Join(top, " ") + "\n    return\n  fi\n  case $words[2] in\n")
		names := make([]string, 0, len(grp))
		for g := range grp {
			names = append(names, g)
		}
		sort.Strings(names)
		for _, g := range names {
			fmt.Fprintf(&b, "    %s) (( CURRENT == 3 )) && { compadd -- %s; return } ;;\n", g, strings.Join(grp[g], " "))
		}
		b.WriteString("    completion) compadd -- bash zsh fish; return ;;\n  esac\n  compadd -- " + globals + "\n}\n_agentgate \"$@\"\n")
		return b.String(), nil
	case "fish":
		var b strings.Builder
		b.WriteString("# fish completion for agentgate: agentgate completion fish > ~/.config/fish/completions/agentgate.fish\n")
		fmt.Fprintf(&b, "complete -c agentgate -f -n '__fish_use_subcommand' -a '%s'\n", strings.Join(top, " "))
		names := make([]string, 0, len(grp))
		for g := range grp {
			names = append(names, g)
		}
		sort.Strings(names)
		for _, g := range names {
			fmt.Fprintf(&b, "complete -c agentgate -f -n '__fish_seen_subcommand_from %s' -a '%s'\n", g, strings.Join(grp[g], " "))
		}
		b.WriteString("complete -c agentgate -f -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'\n")
		for _, f := range strings.Fields(globals) {
			fmt.Fprintf(&b, "complete -c agentgate -l %s\n", strings.TrimPrefix(f, "--"))
		}
		return b.String(), nil
	}
	return "", usageError("completion takes bash, zsh or fish")
}
