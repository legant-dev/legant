package live

import (
	"sync"
	"testing"
)

func TestHubFanout(t *testing.T) {
	h := NewHub(10)
	a, stopA := h.Subscribe(8)
	b, stopB := h.Subscribe(8)
	defer stopA()
	defer stopB()

	h.Publish(Event{Type: "decision", Decision: "ALLOW", Tool: "read_file"})

	for _, ch := range []<-chan Event{a, b} {
		select {
		case e := <-ch:
			if e.Tool != "read_file" || e.Decision != "ALLOW" {
				t.Fatalf("unexpected event %+v", e)
			}
			if e.Time.IsZero() {
				t.Error("Publish should stamp a time")
			}
		default:
			t.Fatal("subscriber did not receive the event")
		}
	}
}

func TestHubDropsOnFullBuffer(t *testing.T) {
	h := NewHub(100)
	ch, stop := h.Subscribe(2)
	defer stop()
	// Publish far more than the buffer without draining; must not block (if it
	// blocked, this goroutine would never finish and the test would time out).
	for i := 0; i < 50; i++ {
		h.Publish(Event{Type: "decision", Tool: "x"})
	}
	// At most the buffer's worth are queued; the rest were dropped, not blocked.
	if got := len(ch); got > 2 {
		t.Fatalf("buffered more than the channel capacity: %d", got)
	}
}

func TestHubUnsubscribeClosesAndIsIdempotent(t *testing.T) {
	h := NewHub(10)
	ch, stop := h.Subscribe(4)
	stop()
	stop() // idempotent — must not panic or double-close

	if _, ok := <-ch; ok {
		t.Error("channel should be closed after unsubscribe")
	}
	if n := h.Subscribers(); n != 0 {
		t.Fatalf("expected 0 subscribers after unsubscribe, got %d", n)
	}
	// Publishing after everyone left is a no-op and must not panic.
	h.Publish(Event{Type: "mint"})
}

func TestHubRecentRing(t *testing.T) {
	h := NewHub(3)
	for i := 0; i < 5; i++ {
		h.Publish(Event{Type: "decision", Tool: string(rune('a' + i))})
	}
	r := h.Recent()
	if len(r) != 3 {
		t.Fatalf("ring should cap at 3, got %d", len(r))
	}
	// Oldest-first, last three published: c, d, e.
	if r[0].Tool != "c" || r[2].Tool != "e" {
		t.Fatalf("ring kept the wrong window: %v", []string{r[0].Tool, r[1].Tool, r[2].Tool})
	}
}

func TestHubNilSafe(t *testing.T) {
	var h *Hub
	h.Publish(Event{Type: "decision"}) // must not panic
	if r := h.Recent(); r != nil {
		t.Error("nil hub Recent should be nil")
	}
	if n := h.Subscribers(); n != 0 {
		t.Error("nil hub has no subscribers")
	}
}

func TestHubConcurrentPublishSubscribe(t *testing.T) {
	h := NewHub(50)
	var wg sync.WaitGroup
	// Churn subscribers while publishing, under -race.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch, stop := h.Subscribe(4)
			for j := 0; j < 20; j++ {
				select {
				case <-ch:
				default:
				}
			}
			stop()
		}()
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				h.Publish(Event{Type: "decision", Tool: "x"})
			}
		}()
	}
	wg.Wait()
}
