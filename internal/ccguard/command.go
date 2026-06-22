package ccguard

import (
	"path/filepath"
	"regexp"
	"strings"
)

// applyPatchFileRE matches the file headers in a Codex/opencode apply_patch
// envelope: "*** Add File: p", "*** Update File: p", "*** Delete File: p",
// "*** Move to: p".
var applyPatchFileRE = regexp.MustCompile(`(?m)^\*\*\*\s+(?:(?:Add|Update|Delete)\s+File|Move\s+to):\s+(.+?)\s*$`)

// applyPatchPaths extracts the absolute, cleaned paths a patch touches, so an
// apply_patch write is path-contained like a Write. An unparseable patch yields
// no paths, which the caller treats as fail-closed when path roots are set.
func applyPatchPaths(patch, cwd string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, m := range applyPatchFileRE.FindAllStringSubmatch(patch, -1) {
		p := absClean(cwd, strings.TrimSpace(m[1]))
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

// catastrophic reports whether a shell command matches an always-refused
// destructive pattern — refused even when shell.exec is granted. `rm` is detected
// with argv-aware parsing (so flag spacing, ordering, and GNU long-forms cannot
// dodge it); the rest are targeted regexes.
func catastrophic(command string) (string, bool) {
	for _, seg := range splitShell(command) {
		if recursiveForceRmOfDanger(seg) {
			return "recursive force-remove of a dangerous path", true
		}
	}
	for _, p := range catastrophicPatterns {
		if p.re.MatchString(command) {
			return p.why, true
		}
	}
	return "", false
}

type catPattern struct {
	why string
	re  *regexp.Regexp
}

var catastrophicPatterns = []catPattern{
	{"fork bomb", regexp.MustCompile(`:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`)},
	{"filesystem format (mkfs)", regexp.MustCompile(`(?i)\bmkfs(\.\w+)?\b`)},
	{"raw write to a block device (dd)", regexp.MustCompile(`(?i)\bdd\b[^|&;]*\bof=/dev/`)},
	{"redirect to a block device", regexp.MustCompile(`(?i)>\s*/dev/(sd|nvme|disk|hd)`)},
	{"chmod 777 of the filesystem root", regexp.MustCompile(`(?i)\bchmod\s+(-[a-z]*\s+)*-?R[a-z]*\s+777\s+/`)},
	{"pipe a download straight into a shell", regexp.MustCompile(`(?i)\b(curl|wget|fetch)\b[^|]*\|\s*(sudo\s+)?\S*(ba|z|c|k|d?a)?sh\b`)},
}

// recursiveForceRmOfDanger reports whether a single command segment is an
// `rm`-family recursive delete aimed at a catastrophic target. It tokenizes argv,
// expands clustered short flags (-rf, -fr, -r -f) and recognizes the GNU
// long-forms (--recursive/--force), so `rm --recursive --force /` and
// `rm -r -f ~` are caught just like `rm -rf /`.
func recursiveForceRmOfDanger(segment string) bool {
	fields := strings.Fields(segment)
	i := skipWrappers(fields)
	if i >= len(fields) || filepath.Base(strings.Trim(fields[i], `"'`)) != "rm" {
		return false
	}
	recursive := false
	var targets []string
	endFlags := false
	for _, tok := range fields[i+1:] {
		switch {
		case tok == "--":
			endFlags = true
		case !endFlags && tok == "--recursive":
			recursive = true
		case !endFlags && tok == "--force":
			// force alone is not the trigger; recursion + dangerous target is.
		case !endFlags && strings.HasPrefix(tok, "--"):
			// other long flag, ignore
		case !endFlags && strings.HasPrefix(tok, "-") && len(tok) > 1:
			for _, c := range tok[1:] {
				if c == 'r' || c == 'R' {
					recursive = true
				}
			}
		default:
			targets = append(targets, tok)
		}
	}
	if !recursive {
		return false
	}
	for _, t := range targets {
		if dangerousRmTarget(t) {
			return true
		}
	}
	return false
}

// dangerousRmTarget reports whether an rm target is catastrophic: the filesystem
// root, the home directory, a bare wildcard, or a top-level system directory.
// Ordinary in-project targets (./node_modules, build/) are NOT flagged.
func dangerousRmTarget(t string) bool {
	t = strings.Trim(t, `"'`)
	switch t {
	case "/", "/*", "~", "~/", "$HOME", "${HOME}", "*", "/.", "/*/", ".", "./", "..", "../":
		return true
	}
	if strings.HasPrefix(t, "~") || strings.HasPrefix(t, "$HOME") || strings.HasPrefix(t, "${HOME}") {
		return true
	}
	if strings.HasPrefix(t, "/") {
		parts := strings.Split(strings.Trim(filepath.Clean(t), "/"), "/")
		if len(parts) <= 1 { // /etc, /usr, or just /
			return true
		}
		switch "/" + parts[0] {
		case "/etc", "/usr", "/var", "/bin", "/sbin", "/lib", "/lib64", "/boot",
			"/root", "/sys", "/proc", "/dev", "/System", "/Library", "/Applications", "/private":
			return true
		}
	}
	return false
}

// skipWrappers returns the index of the real executable token after skipping
// leading VAR=val assignments and sudo/env/etc wrappers.
func skipWrappers(fields []string) int {
	i := 0
	for i < len(fields) && isAssignment(fields[i]) {
		i++
	}
	for i < len(fields) && isWrapper(fields[i]) {
		i++
		for i < len(fields) && (isAssignment(fields[i]) || strings.HasPrefix(fields[i], "-")) {
			i++
		}
	}
	return i
}

// redirectTargets extracts the file targets of output redirections (`>`, `>>`,
// `&>`, `>|`) so they can be path-contained like a Write. Best-effort: device
// targets and fd-dups (`2>&1`) are skipped. This catches the lazy `echo x > /etc/y`
// escape but is NOT a complete shell sandbox (see the package doc).
var redirectRE = regexp.MustCompile(`(?:&?>>?\|?)\s*([^\s|&;<>()]+)`)

func redirectTargets(command string) []string {
	var out []string
	for _, m := range redirectRE.FindAllStringSubmatch(command, -1) {
		t := strings.Trim(m[1], `"'`)
		if t == "" || strings.HasPrefix(t, "/dev/") || strings.HasPrefix(t, "&") {
			continue
		}
		out = append(out, t)
	}
	return out
}
