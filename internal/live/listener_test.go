package live

import (
	"strings"
	"testing"
)

// TestEventValidation guards the trust boundary: the Postgres NOTIFY channel is
// not trusted, so forged or oversized events must be rejected before they can
// reach the (superadmin) console DOM.
func TestEventValidation(t *testing.T) {
	cases := []struct {
		name string
		e    Event
		want bool
	}{
		{"normal decision", Event{Type: "decision", Decision: "ALLOW", Tool: "read_file"}, true},
		{"mint", Event{Type: "mint", Decision: "MINT", Provenance: "user:a → agent:x"}, true},
		{"revoke", Event{Type: "revoke", Decision: "REVOKE", Delegation: "d1"}, true},
		{"empty decision ok", Event{Type: "decision", Decision: ""}, true},
		{"unknown type rejected", Event{Type: "<script>", Decision: "ALLOW"}, false},
		{"forged decision rejected", Event{Type: "decision", Decision: `x" onmouseover=alert(1)`}, false},
		{"oversized field rejected", Event{Type: "mint", Decision: "MINT", Provenance: strings.Repeat("a", maxFieldLen+1)}, false},
	}
	for _, c := range cases {
		if got := valid(c.e); got != c.want {
			t.Errorf("%s: valid()=%v, want %v", c.name, got, c.want)
		}
	}
}
