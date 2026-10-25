// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package fsrules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const accessSource = "../../bpf/fs_access.bpf.c"

// dpathAllowedHooks are the LSM hooks whose programs may reach bpf_d_path.
//
// For a BPF_PROG_TYPE_LSM program the kernel allows bpf_d_path only when the
// attach hook is in its sleepable LSM hook set: bpf_d_path_allowed() returns
// bpf_lsm_is_sleepable_hook() (kernel/trace/bpf_trace.c), which tests the
// sleepable_lsm_hooks BTF set (kernel/bpf/bpf_lsm.c). On 6.8 that set holds the
// hooks below, and others this object does not use; it does not hold
// path_mknod, file_permission, file_mprotect, file_alloc_security or
// file_free_security. One program that breaks the rule fails verification, and
// the guard loads the object's programs together, so every host-control launch
// would fail closed. Add a hook here only after checking it against that set.
var dpathAllowedHooks = map[string]bool{
	"bprm_check_security": true, "file_open": true, "file_receive": true, "inode_getattr": true, "mmap_file": true,
	"path_chmod": true, "path_chown": true, "path_link": true, "path_mkdir": true, "path_rename": true,
	"path_rmdir": true, "path_symlink": true, "path_truncate": true, "path_unlink": true,
}

type bpfProgram struct{ name, section string }

type bpfSource struct {
	programs []bpfProgram
	// refs maps each function, program and macro to the identifiers its body names.
	refs map[string][]string
}

// stripC removes comments and the contents of string and character literals,
// keeping SEC("...") section strings, which the caller needs.
func stripC(src string) string {
	var out strings.Builder
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
			out.WriteByte('\n')
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				return out.String()
			}
			out.WriteString(strings.Repeat("\n", strings.Count(src[i:i+2+end+2], "\n")))
			i += 2 + end + 1
			out.WriteByte(' ')
		case c == '"' || c == '\'':
			j := i + 1
			for j < len(src) && src[j] != c {
				if src[j] == '\\' {
					j++
				}
				j++
			}
			literal := src[i : j+1]
			if c == '"' && strings.HasSuffix(strings.TrimSpace(out.String()), "SEC(") {
				out.WriteString(literal)
			} else {
				out.WriteString(string(c) + string(c))
			}
			i = j
		default:
			out.WriteByte(c)
		}
	}
	return out.String()
}

var (
	identifier = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
	section    = regexp.MustCompile(`SEC\("([^"]*)"\)`)
	bpfProg    = regexp.MustCompile(`BPF_PROG\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)`)
	define     = regexp.MustCompile(`^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)(.*)$`)
)

// parseBPF finds every top-level function, BPF program and macro, and what each
// body refers to. A name passed as a value (a bpf_loop callback) counts as a
// reference, so the analysis over-approximates calls rather than missing one.
func parseBPF(src string) (bpfSource, error) {
	out := bpfSource{refs: map[string][]string{}}
	lines := strings.Split(stripC(src), "\n")
	var code strings.Builder
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			full := line
			for strings.HasSuffix(strings.TrimSpace(full), "\\") && i+1 < len(lines) {
				i++
				full = strings.TrimSuffix(strings.TrimSpace(full), "\\") + " " + lines[i]
			}
			if m := define.FindStringSubmatch(full); m != nil {
				out.refs[m[1]] = identifier.FindAllString(m[2], -1)
			}
			code.WriteString("\n")
			continue
		}
		code.WriteString(line + "\n")
	}
	text := code.String()
	header := strings.Builder{}
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case ';':
			header.Reset()
		case '{':
			depth, j := 1, i+1
			for ; j < len(text) && depth > 0; j++ {
				if text[j] == '{' {
					depth++
				} else if text[j] == '}' {
					depth--
				}
			}
			if depth != 0 {
				return out, fmt.Errorf("unbalanced braces at byte %d", i)
			}
			head, body := header.String(), text[i+1:j-1]
			header.Reset()
			i = j - 1
			name, sec := "", ""
			if m := section.FindStringSubmatch(head); m != nil {
				sec = m[1]
				head = section.ReplaceAllString(head, " ")
			}
			if m := bpfProg.FindStringSubmatch(head); m != nil {
				name = m[1]
			} else if open := strings.Index(head, "("); open > 0 && !strings.Contains(head, "=") && strings.HasSuffix(strings.TrimSpace(head), ")") {
				words := identifier.FindAllString(head[:open], -1)
				if len(words) > 0 {
					name = words[len(words)-1]
				}
			}
			if name == "" {
				if sec != "" {
					return out, fmt.Errorf("section %q has no recognizable program name", sec)
				}
				continue // a struct, map or initializer
			}
			if sec != "" && sec != ".maps" && sec != "license" {
				out.programs = append(out.programs, bpfProgram{name, sec})
			}
			out.refs[name] = identifier.FindAllString(body, -1)
		default:
			header.WriteByte(text[i])
		}
	}
	return out, nil
}

// reaches reports whether name refers, directly or through other definitions in
// the file, to target.
func (s bpfSource) reaches(name, target string) bool {
	seen := map[string]bool{}
	var walk func(string) bool
	walk = func(n string) bool {
		if seen[n] {
			return false
		}
		seen[n] = true
		for _, ref := range s.refs[n] {
			if ref == target {
				return true
			}
			if _, known := s.refs[ref]; known && walk(ref) {
				return true
			}
		}
		return false
	}
	return walk(name)
}

// dpathViolations lists every program that reaches bpf_d_path from a section
// outside dpathAllowedHooks.
func dpathViolations(s bpfSource) []string {
	bad := []string{}
	for _, p := range s.programs {
		hook, lsm := strings.CutPrefix(p.section, "lsm/")
		if s.reaches(p.name, "bpf_d_path") && (!lsm || !dpathAllowedHooks[hook]) {
			bad = append(bad, p.name+" ("+p.section+")")
		}
	}
	sort.Strings(bad)
	return bad
}

func TestDPathOnlyFromSleepableHooks(t *testing.T) {
	raw, err := os.ReadFile(accessSource)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "bpf_d_path(") {
		t.Fatal("the object no longer calls bpf_d_path; this check would be vacuous")
	}
	parsed, err := parseBPF(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if bad := dpathViolations(parsed); len(bad) != 0 {
		t.Fatalf("bpf_d_path is reachable from hooks outside the sleepable LSM set: %v", bad)
	}
	// The parsed programs are exactly the hooks the guard attaches.
	got, sections := []string{}, map[string]string{}
	for _, p := range parsed.programs {
		got = append(got, p.name)
		sections[p.name] = p.section
	}
	want := AccessProfile().LSMPrograms
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("parsed programs %v differ from AccessProfile %v", got, want)
	}
	// Spot checks keep the analysis honest in both directions.
	for _, name := range []string{"fs_open", "fs_exec", "fs_mkdir", "fs_rename", "fs_mmap"} {
		if !parsed.reaches(name, "bpf_d_path") {
			t.Fatalf("%s no longer reaches bpf_d_path; the parser lost a call", name)
		}
	}
	if sections["fs_create"] != "lsm/path_mknod" || parsed.reaches("fs_create", "bpf_d_path") {
		t.Fatal("path_mknod reaches bpf_d_path")
	}
}

func TestDPathAnalysisFindsIndirectReferences(t *testing.T) {
	base := `
#define P 4096
static __always_inline int resolve(struct path *p){char b[P];return bpf_d_path(p,b,P);}
static long walk(__u32 i,void *ctx){return resolve(ctx);}
`
	cases := map[string]struct {
		src  string
		want []string
	}{
		"direct":     {base + `SEC("lsm/path_mknod") int BPF_PROG(mk,struct path *d){return resolve(d);}`, []string{"mk (lsm/path_mknod)"}},
		"callback":   {base + `SEC("lsm/path_mknod") int BPF_PROG(mk,struct path *d){return bpf_loop(1,walk,d,0);}`, []string{"mk (lsm/path_mknod)"}},
		"macro":      {base + "#define R(x) \\\n  resolve(x)\n" + `SEC("lsm/file_permission") int BPF_PROG(use,struct file *f){return R(0);}`, []string{"use (lsm/file_permission)"}},
		"other type": {base + `SEC("fentry/vfs_read") int BPF_PROG(tr,struct file *f){return resolve(0);}`, []string{"tr (fentry/vfs_read)"}},
		"allowed":    {base + `SEC("lsm/file_open") int BPF_PROG(op,struct file *f){return resolve(0);}`, []string{}},
		"comment and string": {base + `// bpf_d_path(
SEC("lsm/path_mknod") int BPF_PROG(mk,struct path *d){/* resolve(d) */ char *s="bpf_d_path resolve"; return s[0]=='/';}`, []string{}},
	}
	for name, c := range cases {
		parsed, err := parseBPF(c.src)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := dpathViolations(parsed); strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Fatalf("%s: got %v want %v", name, got, c.want)
		}
	}
}

// TestDPathInCompiledObject repeats the check on the compiled instructions when
// clang and the libbpf headers are present. The source check above always runs.
func TestDPathInCompiledObject(t *testing.T) {
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang is not installed; the source-level check still ran")
	}
	object := filepath.Join(t.TempDir(), "fs_access.o")
	build := exec.Command(clang, "-O2", "-g", "-target", "bpf", "-Wall", "-D__TARGET_ARCH_x86", "-I/usr/include/x86_64-linux-gnu", "-c", accessSource, "-o", object)
	if output, buildErr := build.CombinedOutput(); buildErr != nil {
		t.Skipf("the BPF object does not build here (%v): %s", buildErr, output)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	callers := 0
	for name, program := range spec.Programs {
		for _, ins := range program.Instructions {
			if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnDPath) {
				hook, lsm := strings.CutPrefix(program.SectionName, "lsm/")
				if !lsm || !dpathAllowedHooks[hook] {
					t.Fatalf("%s (%s) calls bpf_d_path", name, program.SectionName)
				}
				callers++
				break
			}
		}
	}
	if callers == 0 {
		t.Fatal("no compiled program calls bpf_d_path; the check would be vacuous")
	}
}

// functionBody returns the stripped body of the BPF program or function name.
func functionBody(t *testing.T, src, name string) string {
	t.Helper()
	text := stripC(src)
	start := -1
	for _, head := range []string{"BPF_PROG(" + name + ",", " " + name + "("} {
		if i := strings.Index(text, head); i >= 0 && (start < 0 || i < start) {
			start = i
		}
	}
	if start < 0 {
		t.Fatalf("%s is absent", name)
	}
	open := strings.Index(text[start:], "{")
	if open < 0 {
		t.Fatalf("%s has no body", name)
	}
	depth, i := 0, start+open
	for ; i < len(text); i++ {
		if text[i] == '{' {
			depth++
		} else if text[i] == '}' {
			depth--
			if depth == 0 {
				break
			}
		}
	}
	return strings.Join(strings.Fields(text[start+open+1:i]), "")
}

// statements splits a compacted body at semicolons, keeping each if with its
// guarded return.
func statements(body string) []string {
	out := []string{}
	for _, s := range strings.Split(body, ";") {
		if s = strings.Trim(s, "{}"); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// TestCreateAllowsOnlyAnOpenThatCreates pins the conditions under which
// path_mknod lets a creation through (see the comment on fs_create): a
// regular file with no device number, created by the walk of an open(O_CREAT)
// in progress, during an x86-64 open-family syscall. Every other path denies.
// A kernel that changes one of these internals makes open(O_CREAT) of a new
// file fail closed; this test only keeps the source from loosening them.
func TestCreateAllowsOnlyAnOpenThatCreates(t *testing.T) {
	raw, err := os.ReadFile(accessSource)
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	parsed, err := parseBPF(src)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.reaches("fs_create", "bpf_d_path") {
		t.Fatal("path_mknod reaches bpf_d_path")
	}
	for name, value := range map[string]string{"S_IFMT_": "0170000", "S_IFREG_": "0100000", "FMODE_CREATED_": "0x100000",
		"LOOKUP_OPEN_": "0x0100", "LOOKUP_CREATE_": "0x0200", "NR_OPEN_": "2", "NR_CREAT_": "85", "NR_OPENAT_": "257", "NR_OPENAT2_": "437"} {
		if !regexp.MustCompile(`(?m)^#define ` + name + ` ` + value + `$`).MatchString(src) {
			t.Fatalf("%s is no longer %s", name, value)
		}
	}
	allows := 0
	for _, s := range statements(functionBody(t, src, "fs_create")) {
		switch {
		case !strings.Contains(s, "return"):
		case strings.HasSuffix(s, "returnret"), strings.Contains(s, "returnmutation_denied("):
		case s == "if(!bpf_map_lookup_elem(&owned,&domain))return0":
			// A task outside every managed domain is not this guard's business.
		case s == "if((mode&S_IFMT_)==S_IFREG_&&!dev&&open_creates(dir,task))return0":
			allows++
		default:
			t.Fatalf("fs_create has an unreviewed return: %s", s)
		}
	}
	if allows != 1 {
		t.Fatalf("fs_create allows in %d places", allows)
	}
	want := []string{
		"structnameidata*nd=BPF_CORE_READ(task,nameidata)",
		"if(!nd)return0",
		"if((BPF_CORE_READ(nd,flags)&(LOOKUP_OPEN_|LOOKUP_CREATE_))!=(LOOKUP_OPEN_|LOOKUP_CREATE_))return0",
		"if((__u64)dir!=(__u64)nd+bpf_core_field_offset(structnameidata,path))return0",
		"structpt_regs*regs=(structpt_regs*)bpf_task_pt_regs(task)",
		"if(!regs)return0",
		"unsignedlongnr=BPF_CORE_READ(regs,orig_ax)",
		"returnnr==NR_OPEN_||nr==NR_CREAT_||nr==NR_OPENAT_||nr==NR_OPENAT2_",
	}
	if got := statements(functionBody(t, src, "open_creates")); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("open_creates differs from its reviewed form:\n%s", strings.Join(got, "\n"))
	}
	// The kernel field names are the ones CO-RE resolves (checked against BTF by hand).
	for _, decl := range []string{
		"struct nameidata {struct path path;unsigned int flags;} __attribute__((preserve_access_index));",
		"struct task_struct {__u64 start_boottime;struct nameidata *nameidata;} __attribute__((preserve_access_index));",
		"struct pt_regs {unsigned long orig_ax;} __attribute__((preserve_access_index));",
	} {
		if !strings.Contains(src, decl) {
			t.Fatalf("CO-RE declaration changed: %s", decl)
		}
	}
}
