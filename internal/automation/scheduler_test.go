package automation

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestRunDueSelectsEnabledSchedulesDeterministically(t *testing.T) {
	runner := &fakeRunner{}
	scheduler, err := NewScheduler(runner, 2)
	if err != nil {
		t.Fatalf("create scheduler: %v", err)
	}
	clock := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	scheduler.now = func() time.Time { return clock }

	results := scheduler.RunDue(context.Background(), []Schedule{
		{ID: "later", TenantID: "tenant", Target: "later.example", Interval: time.Minute, NextRun: clock.Add(-time.Minute), Enabled: true},
		{ID: "disabled", TenantID: "tenant", Target: "disabled.example", Interval: time.Minute, NextRun: clock.Add(-time.Hour), Enabled: false},
		{ID: "future", TenantID: "tenant", Target: "future.example", Interval: time.Minute, NextRun: clock.Add(time.Minute), Enabled: true},
		{ID: "earlier", TenantID: "tenant", Target: "earlier.example", Interval: time.Minute, NextRun: clock.Add(-time.Hour), Enabled: true},
	})

	if len(results) != 2 || results[0].ScheduleID != "earlier" || results[1].ScheduleID != "later" {
		t.Fatalf("unexpected due results: %+v", results)
	}
}

func TestRunDueHonorsCancellation(t *testing.T) {
	runner := &blockingRunner{}
	scheduler, err := NewScheduler(runner, 1)
	if err != nil {
		t.Fatalf("create scheduler: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results := scheduler.RunDue(ctx, []Schedule{{ID: "one", TenantID: "tenant", Target: "one.example", Interval: time.Minute, NextRun: time.Now().Add(-time.Minute), Enabled: true}})
	if len(results) != 1 || results[0].Err != context.Canceled {
		t.Fatalf("expected canceled result: %+v", results)
	}
}

func TestValidateScheduleRejectsUnsafeInterval(t *testing.T) {
	err := ValidateSchedule(Schedule{ID: "one", TenantID: "tenant", Target: "one.example", Interval: time.Second, NextRun: time.Now()})
	if err == nil {
		t.Fatal("expected invalid interval")
	}
}

type fakeRunner struct {
	mutex sync.Mutex
	seen  []string
}

func (runner *fakeRunner) Run(context.Context, Schedule) error { return nil }

type blockingRunner struct{}

func (blockingRunner) Run(ctx context.Context, _ Schedule) error { return ctx.Err() }
