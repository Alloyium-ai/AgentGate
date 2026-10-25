// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"context"
	"flag"
	"strings"
)

// IdentityLink is one person: subjects an administrator linked as the same
// human, so none of them decides a launch another requested.
type IdentityLink struct {
	Person   string   `json:"person"`
	Subjects []string `json:"subjects"`
	LinkedBy string   `json:"linked_by"`
	LinkedAt string   `json:"linked_at"`
}

func init() {
	register(&command{name: "identity ls", summary: "List subjects linked as one person (admin).", setup: func(fs *flag.FlagSet) runner {
		return func(ctx context.Context, e *env, args, _ []string) error {
			if len(args) != 0 {
				return usageError("identity ls takes no arguments")
			}
			return e.identityList(ctx)
		}
	}})
	register(&command{name: "identity link", args: "SUBJECT SUBJECT...", summary: "Link subjects of one person: none of them may approve a launch another requested (admin).",
		help: `  --reason TEXT
A subject is local:<username> or oidc:<issuer subject>, as launches show it in requested_by. A link only
widens the refusal of self-approval; it grants no role. Linking a subject that already belongs to a person
merges the two (at most 8 subjects).`,
		setup: func(fs *flag.FlagSet) runner {
			reason := fs.String("reason", "", "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) < 2 || len(args) > 8 {
					return usageError("identity link takes 2 to 8 subjects (local:<username>, oidc:<issuer subject>)")
				}
				return e.identityLink(ctx, args, *reason)
			}
		}})
	register(&command{name: "identity unlink", args: "SUBJECT", summary: "Remove a subject from its person (admin; never your own group).",
		help: "  --reason TEXT\nAnother administrator must unlink a group that holds your own subject.",
		setup: func(fs *flag.FlagSet) runner {
			reason := fs.String("reason", "", "")
			return func(ctx context.Context, e *env, args, _ []string) error {
				if len(args) != 1 {
					return usageError("identity unlink takes one subject")
				}
				return e.identityUnlink(ctx, args[0], *reason)
			}
		}})
}

func (e *env) identityList(ctx context.Context) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	var list items[IdentityLink]
	raw, err := c.get(ctx, apiPrefix+"/identity-links", nil, &list)
	if err != nil {
		return err
	}
	return e.emit(raw, func() error {
		if len(list.Items) == 0 {
			e.p.note("No subjects are linked: each account counts as its own person when launches are approved.")
			return nil
		}
		rows := [][]string{}
		for _, p := range list.Items {
			rows = append(rows, []string{short(p.Person), strings.Join(p.Subjects, ", "), p.LinkedBy, p.LinkedAt})
		}
		e.p.table([]string{"PERSON", "SUBJECTS", "LAST LINKED BY", "AT"}, rows)
		return nil
	})
}

func (e *env) identityLink(ctx context.Context, subjects []string, reason string) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	if reason, err = defaultReason(reason, "Link "+strings.Join(subjects, ", ")+" as one person with the agentgate CLI"); err != nil {
		return err
	}
	var link IdentityLink
	raw, err := c.mutate(ctx, "POST", apiPrefix+"/identity-links", map[string]any{"subjects": subjects, "reason": reason}, true, &link)
	if err != nil {
		return err
	}
	return e.emit(raw, func() error {
		e.p.line("Linked as one person: %s. None of them may approve a launch another requested.", strings.Join(link.Subjects, ", "))
		return nil
	})
}

func (e *env) identityUnlink(ctx context.Context, subject, reason string) error {
	c, err := e.authed()
	if err != nil {
		return err
	}
	if reason, err = defaultReason(reason, "Unlink "+subject+" with the agentgate CLI"); err != nil {
		return err
	}
	var out struct {
		Subjects []string `json:"subjects"`
	}
	raw, err := c.mutate(ctx, "DELETE", apiPrefix+"/identity-links", map[string]any{"subject": subject, "reason": reason}, true, &out)
	if err != nil {
		return err
	}
	return e.emit(raw, func() error {
		if len(out.Subjects) == 0 {
			e.p.line("Unlinked %s; its person had no other linked subject left.", subject)
		} else {
			e.p.line("Unlinked %s; still linked: %s.", subject, strings.Join(out.Subjects, ", "))
		}
		return nil
	})
}
