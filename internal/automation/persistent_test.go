package automation

import (
	"context"
	"testing"
	"time"
)

func TestRunDueFromStoreClaimsAndCompletes(t *testing.T) {
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	store := &fakeScheduleStore{due: []Schedule{{ID: "schedule-1", TenantID: "tenant", Target: "example.com", Interval: time.Minute, NextRun: now.Add(-time.Minute), Enabled: true}}}
	scheduler, err := NewScheduler(&fakeRunner{}, 1)
	if err != nil {
		t.Fatalf("create scheduler: %v", err)
	}

	results, err := scheduler.RunDueFromStore(context.Background(), store, "worker-1", now, time.Minute, 10)
	if err != nil {
		t.Fatalf("run due schedules: %v", err)
	}
	if len(results) != 1 || !store.claimed || !store.completed {
		t.Fatalf("expected claim and completion: results=%+v store=%+v", results, store)
	}
}

type fakeScheduleStore struct {
	due       []Schedule
	claimed   bool
	completed bool
}

func (store *fakeScheduleStore) Due(context.Context, time.Time, int) ([]Schedule, error) {
	return store.due, nil
}

func (store *fakeScheduleStore) Claim(context.Context, string, string, time.Time, time.Duration) (bool, error) {
	store.claimed = true
	return true, nil
}

func (store *fakeScheduleStore) Complete(context.Context, string, string, time.Time, error) error {
	store.completed = true
	return nil
}
