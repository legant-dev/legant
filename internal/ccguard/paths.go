package ccguard

import (
	"net/url"
	"path/filepath"
	"strings"
)

// hasScopeIn reports whether scope is present in the space-delimited scope string.
func hasScopeIn(scopeStr, scope string) bool {
	for _, s := range strings.Fields(scopeStr) {
		if s == scope {
			return true
		}
	}
	return false
}

// absClean resolves p to an absolute, cleaned path. A relative p is joined onto
// cwd first. This is the traversal-safe normalization that makes a later prefix
// check sound: "./src/../../etc/passwd" collapses to its true absolute target
// before it is compared against the allowed roots.
func absClean(cwd, p string) string {
	if p == "" {
		return ""
	}
	if !filepath.IsAbs(p) {
		if cwd != "" {
			p = filepath.Join(cwd, p)
		}
	}
	return filepath.Clean(p)
}

// absResolve resolves each path against cwd into an absolute, cleaned path,
// dropping empties — used to normalize allow/deny roots before a containment check.
func absResolve(paths []string, cwd string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if a := absClean(cwd, p); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// realPath resolves symlinks on the longest EXISTING prefix of p, keeping any
// not-yet-created trailing components lexical. This defeats a symlink planted
// inside an allowed root that points outside it: the link is resolved to its true
// target before the containment check, and a Write to a not-yet-existing file is
// still resolved through its symlinked parent directories. Falls back to p.
func realPath(p string) string {
	if p == "" {
		return p
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	var rest []string
	cur := p
	for {
		parent := filepath.Dir(cur)
		rest = append([]string{filepath.Base(cur)}, rest...)
		if r, err := filepath.EvalSymlinks(parent); err == nil {
			return filepath.Join(append([]string{r}, rest...)...)
		}
		if parent == cur { // reached the root without resolving
			return p
		}
		cur = parent
	}
}

func realPaths(ps []string) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = realPath(p)
	}
	return out
}

// contained reports whether target (an absolute, cleaned path) is at or below at
// least one of roots (absolute, cleaned). It uses filepath.Rel and rejects any
// result that escapes the root with "..", so a sibling or parent directory never
// matches. A root of "/" contains everything; an exact match counts.
func contained(target string, roots []string) bool {
	for _, root := range roots {
		rel, err := filepath.Rel(root, target)
		if err != nil {
			continue
		}
		if rel == "." {
			return true
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		return true
	}
	return false
}

// commandExecutables extracts the executable name(s) a shell command invokes. It
// splits on the common control operators (; | & && ||, newlines), and for each
// segment skips leading VAR=value assignments and the env/sudo/command wrappers,
// then takes the basename of the first remaining token. It is a pragmatic parser
// for an allow-list check, not a full shell grammar — the always-on destructive
// denylist is the backstop for anything it misparses.
func commandExecutables(command string) []string {
	segments := splitShell(command)
	seen := map[string]struct{}{}
	var out []string
	for _, seg := range segments {
		fields := strings.Fields(seg)
		i := 0
		// skip leading FOO=bar environment assignments
		for i < len(fields) && isAssignment(fields[i]) {
			i++
		}
		// skip wrappers that take the *next* token as the real command
		for i < len(fields) && isWrapper(fields[i]) {
			i++
			for i < len(fields) && (isAssignment(fields[i]) || strings.HasPrefix(fields[i], "-")) {
				i++ // skip wrapper flags / inline assignments (e.g. `env -i`, `sudo -u x`)
			}
		}
		if i >= len(fields) {
			continue
		}
		exe := filepath.Base(strings.Trim(fields[i], "\"'`"))
		if exe == "" || exe == "." {
			continue
		}
		if _, ok := seen[exe]; ok {
			continue
		}
		seen[exe] = struct{}{}
		out = append(out, exe)
	}
	return out
}

func isAssignment(tok string) bool {
	eq := strings.IndexByte(tok, '=')
	return eq > 0 && !strings.ContainsAny(tok[:eq], "/\\ ")
}

func isWrapper(tok string) bool {
	switch filepath.Base(tok) {
	case "sudo", "env", "command", "nice", "nohup", "time", "xargs", "doas":
		return true
	}
	return false
}

// splitShell breaks a command line into segments on the operators that start a
// new simple command, so each segment's first token is a candidate executable.
func splitShell(command string) []string {
	repl := command
	for _, op := range []string{"&&", "||", ";", "|", "&", "\n", "`", "$(", ")"} {
		repl = strings.ReplaceAll(repl, op, "\x00")
	}
	parts := strings.Split(repl, "\x00")
	var out []string
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// hostOf returns the lowercased host of a URL, or "" if it cannot be parsed.
func hostOf(rawURL string) string {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
