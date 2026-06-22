package delegation_test

import (
	"testing"
	"time"

	"github.com/legant-dev/legant/internal/delegation"
)

func TestTimeWindowAllows(t *testing.T) {
	at := time.Date(2026, 6, 15, 10, 30, 0, 0, time.UTC) // a Monday, 10:30 UTC
	wd := int(at.Weekday())

	in := &delegation.TimeWindow{Weekdays: []int{wd}, StartMin: 9 * 60, EndMin: 17 * 60}
	if !in.Allows(at) {
		t.Error("10:30 on the allowed weekday within 09:00-17:00 should be allowed")
	}
	if in.Allows(time.Date(2026, 6, 15, 8, 0, 0, 0, time.UTC)) {
		t.Error("08:00 is before the 09:00 window start; should be denied")
	}
	wrongDay := &delegation.TimeWindow{Weekdays: []int{(wd + 1) % 7}, StartMin: 0, EndMin: 1439}
	if wrongDay.Allows(at) {
		t.Error("a non-allowed weekday should be denied")
	}
	badTZ := &delegation.TimeWindow{TZ: "Not/AZone", StartMin: 0, EndMin: 1439}
	if badTZ.Allows(at) {
		t.Error("an unknown timezone must fail closed (deny)")
	}
}

func TestPermitTimeWindow(t *testing.T) {
	c := delegation.Constraints{TimeWindow: &delegation.TimeWindow{StartMin: 9 * 60, EndMin: 17 * 60}}
	if err := c.Permit(delegation.Action{Scope: "x", At: time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)}); err != nil {
		t.Errorf("in-window action should pass: %v", err)
	}
	if err := c.Permit(delegation.Action{Scope: "x", At: time.Date(2026, 6, 15, 20, 0, 0, 0, time.UTC)}); err == nil {
		t.Error("out-of-window action should be denied")
	}
}

func TestTightenWindowAndRate(t *testing.T) {
	p := delegation.Constraints{
		TimeWindow: &delegation.TimeWindow{Weekdays: []int{1, 2, 3, 4, 5}, StartMin: 8 * 60, EndMin: 18 * 60},
		Rate:       &delegation.RateLimit{MaxPerHour: 10},
	}
	c := delegation.Constraints{
		TimeWindow: &delegation.TimeWindow{Weekdays: []int{3, 4, 5, 6}, StartMin: 9 * 60, EndMin: 17 * 60},
		Rate:       &delegation.RateLimit{MaxPerHour: 3},
	}
	out := delegation.Tighten(p, c)
	if out.Rate.MaxPerHour != 3 {
		t.Errorf("rate = %d, want the stricter 3", out.Rate.MaxPerHour)
	}
	if out.TimeWindow.StartMin != 9*60 || out.TimeWindow.EndMin != 17*60 {
		t.Errorf("minute range = [%d,%d], want intersection [540,1020]", out.TimeWindow.StartMin, out.TimeWindow.EndMin)
	}
	for _, d := range out.TimeWindow.Weekdays {
		if d == 1 || d == 2 || d == 6 {
			t.Errorf("weekday %d should not survive the intersection {3,4,5}", d)
		}
	}
}

// The escalation fix: tightening two DISJOINT non-empty allow-lists must deny
// everything, never collapse to the empty (unrestricted) list.
func TestTightenDisjointDeniesNotWidens(t *testing.T) {
	out := delegation.Tighten(
		delegation.Constraints{Categories: []string{"travel"}},
		delegation.Constraints{Categories: []string{"meals"}},
	)
	if err := out.Permit(delegation.Action{Scope: "x", Category: "travel"}); err == nil {
		t.Error("disjoint category intersection must deny the parent's category, not widen")
	}
	if err := out.Permit(delegation.Action{Scope: "x", Category: "meals"}); err == nil {
		t.Error("disjoint category intersection must deny the child's category too")
	}
	// The deny-all sentinel must also deny an action that omits the category — it
	// must never fail open just because the dimension is left empty.
	if err := out.Permit(delegation.Action{Scope: "x"}); err == nil {
		t.Error("deny-all sentinel must deny a category-less action (no fail-open)")
	}

	// Disjoint weekdays must likewise match no day.
	pw := delegation.Constraints{TimeWindow: &delegation.TimeWindow{Weekdays: []int{1}, StartMin: 0, EndMin: 1439}}
	cw := delegation.Constraints{TimeWindow: &delegation.TimeWindow{Weekdays: []int{2}, StartMin: 0, EndMin: 1439}}
	outw := delegation.Tighten(pw, cw)
	base := time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC) // Sunday
	for d := 0; d < 7; d++ {
		if outw.TimeWindow.Allows(base.AddDate(0, 0, d)) {
			t.Errorf("disjoint weekdays must deny every day; allowed offset %d", d)
		}
	}
}

func TestTightenWindowCrossTZKeepsParent(t *testing.T) {
	p := delegation.Constraints{TimeWindow: &delegation.TimeWindow{TZ: "UTC", StartMin: 8 * 60, EndMin: 18 * 60}}
	c := delegation.Constraints{TimeWindow: &delegation.TimeWindow{TZ: "America/New_York", StartMin: 0, EndMin: 1439}}
	out := delegation.Tighten(p, c)
	if out.TimeWindow.TZ != "UTC" || out.TimeWindow.StartMin != 8*60 || out.TimeWindow.EndMin != 18*60 {
		t.Errorf("cross-tz tighten should keep the parent window, got %+v", out.TimeWindow)
	}
}
