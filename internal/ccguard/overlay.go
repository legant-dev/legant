package ccguard

import (
	"encoding/json"
	"os"
	"sort"
)

// Overlay is a LOCAL, deny-only restriction layer applied on top of the signed
// delegation token. It can ONLY add denials — never grant, widen, or re-enable
// anything — so it preserves the token-as-ceiling model: edit it freely from the
// CLI or a UI to tighten what an agent may do, and it can never exceed what the
// delegation already permits. An empty or missing overlay changes nothing, so
// installing this layer cannot regress existing behavior.
type Overlay struct {
	DenyPaths []string `json:"deny_paths,omitempty"` // paths refused (in addition to the token's)
	DenyCmds  []string `json:"deny_cmds,omitempty"`  // shell executables refused
	DenyHosts []string `json:"deny_hosts,omitempty"` // net.fetch hosts refused
	DenyTools []string `json:"deny_tools,omitempty"` // tool names refused outright
}

// Empty reports whether the overlay imposes no additional restriction.
func (o *Overlay) Empty() bool {
	return o == nil || len(o.DenyPaths)+len(o.DenyCmds)+len(o.DenyHosts)+len(o.DenyTools) == 0
}

// LoadOverlay reads an overlay JSON file. A MISSING file is (nil, nil): no
// overlay, no error. A malformed file returns an error the caller treats as a
// non-fatal warning — the signed token still fully enforces regardless.
func LoadOverlay(path string) (*Overlay, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var o Overlay
	if err := json.Unmarshal(b, &o); err != nil {
		return nil, err
	}
	return &o, nil
}

// SaveOverlay writes a normalized (sorted, deduplicated) overlay JSON file.
func SaveOverlay(path string, o *Overlay) error {
	o.normalize()
	b, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// Add merges deny rules into the overlay (deduplicated on normalize).
func (o *Overlay) Add(paths, cmds, hosts, tools []string) {
	o.DenyPaths = append(o.DenyPaths, paths...)
	o.DenyCmds = append(o.DenyCmds, cmds...)
	o.DenyHosts = append(o.DenyHosts, hosts...)
	o.DenyTools = append(o.DenyTools, tools...)
	o.normalize()
}

// Remove drops deny rules from the overlay. Because the overlay only ever holds
// ADDED denials, removing one merely un-does a local restriction — it can never
// grant anything the token denies, so it cannot widen past the ceiling.
func (o *Overlay) Remove(paths, cmds, hosts, tools []string) {
	o.DenyPaths = without(o.DenyPaths, paths)
	o.DenyCmds = without(o.DenyCmds, cmds)
	o.DenyHosts = without(o.DenyHosts, hosts)
	o.DenyTools = without(o.DenyTools, tools)
	o.normalize()
}

func (o *Overlay) normalize() {
	o.DenyPaths = dedupSort(o.DenyPaths)
	o.DenyCmds = dedupSort(o.DenyCmds)
	o.DenyHosts = dedupSort(o.DenyHosts)
	o.DenyTools = dedupSort(o.DenyTools)
}

func dedupSort(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func without(set, drop []string) []string {
	rm := map[string]struct{}{}
	for _, d := range drop {
		rm[d] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for _, s := range set {
		if _, ok := rm[s]; !ok {
			out = append(out, s)
		}
	}
	return out
}
