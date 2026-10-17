// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package syscallrules

import (
	"reflect"
	"testing"
)

func TestCommonProfileRequiresOriginAndOutcomeLinks(t *testing.T) {
	p := RuntimeProfile()
	if p.Initialize == nil || p.EventsMap != "audit_events" || p.CountersMap != "audit_stats" || len(p.LSMPrograms) != 0 || len(p.CgroupPrograms) != 0 || len(p.TracepointPrograms) != 3 {
		t.Fatal("the complete observer profile differs")
	}
	got := []string{}
	for _, h := range p.TracepointPrograms {
		got = append(got, h.Name+":"+h.Group+"/"+h.Event)
	}
	if !reflect.DeepEqual(got, []string{"audit_sys_enter:raw_syscalls/sys_enter", "audit_sys_exit:raw_syscalls/sys_exit", "audit_task_exit:sched/sched_process_exit"}) {
		t.Fatal(got)
	}
}
