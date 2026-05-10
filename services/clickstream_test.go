package services

import (
	"sync"
	"testing"
	"time"

	"tiny-url/models"
)

func TestClickStreamPubSub(t *testing.T) {
	cs := NewClickStream()
	subA := cs.Subscribe("code1")
	defer subA.Close()
	subB := cs.Subscribe("code1")
	defer subB.Close()
	subOther := cs.Subscribe("code2")
	defer subOther.Close()

	ev := models.ClickEvent{At: time.Now(), UAClass: "desktop"}
	cs.Publish("code1", ev)

	gotA := drainOne(t, subA.C(), 100*time.Millisecond)
	gotB := drainOne(t, subB.C(), 100*time.Millisecond)
	if gotA == nil || gotB == nil {
		t.Errorf("both subscribers for code1 should receive the event")
	}
	if drainOne(t, subOther.C(), 50*time.Millisecond) != nil {
		t.Errorf("subscriber for code2 should NOT receive code1's event")
	}
}

func TestClickStreamUnsubscribeRemovesChannel(t *testing.T) {
	cs := NewClickStream()
	sub := cs.Subscribe("c")
	if cs.SubscriberCount("c") != 1 {
		t.Fatalf("count after Subscribe = %d, want 1", cs.SubscriberCount("c"))
	}
	sub.Close()
	if cs.SubscriberCount("c") != 0 {
		t.Errorf("count after Close = %d, want 0", cs.SubscriberCount("c"))
	}
	// Idempotent — calling Close twice should not panic.
	sub.Close()
}

func TestClickStreamFullBufferDropsRatherThanBlocks(t *testing.T) {
	// A subscriber that never reads should NOT block subsequent
	// Publish calls — the load-test scenario where a hung tab can't
	// stall the redirect path.
	cs := NewClickStream()
	sub := cs.Subscribe("c")
	defer sub.Close()

	// Buffer is 8 in clickstream.go; publish 1000 to force drops.
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			cs.Publish("c", models.ClickEvent{At: time.Now()})
		}
		close(done)
	}()

	select {
	case <-done:
		// Publish loop returned without blocking — pass.
	case <-time.After(2 * time.Second):
		t.Fatalf("Publish blocked on a slow subscriber")
	}
}

func TestClickStreamConcurrentSubscribersAndPublishers(t *testing.T) {
	// Smoke test for races in the subscription map. Run with -race for
	// real coverage; the assertions here just check we don't deadlock or
	// crash.
	cs := NewClickStream()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				sub := cs.Subscribe("c")
				cs.Publish("c", models.ClickEvent{At: time.Now()})
				_ = drainOne(t, sub.C(), 50*time.Millisecond)
				sub.Close()
			}
		}()
	}
	wg.Wait()
}

// drainOne reads one event with a deadline. Returns nil on timeout.
func drainOne(t *testing.T, ch <-chan models.ClickEvent, deadline time.Duration) *models.ClickEvent {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			return nil
		}
		return &ev
	case <-time.After(deadline):
		return nil
	}
}
