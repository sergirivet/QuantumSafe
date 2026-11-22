package automation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

var ErrInvalidSchedule = errors.New("invalid schedule")

type Schedule struct {
	ID         string        `json:"id"`
	TenantID   string        `json:"tenant_id"`
	Target     string        `json:"target"`
	Interval   time.Duration `json:"interval"`
	NextRun    time.Time     `json:"next_run"`
	Enabled    bool          `json:"enabled"`
	LeaseOwner string        `json:"lease_owner,omitempty"`
	LeaseUntil time.Time     `json:"lease_until,omitempty"`
}

type RunResult struct {
	ScheduleID string    `json:"schedule_id"`
	Target     string    `json:"target"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Err        error     `json:"-"`
}

type Runner interface {
	Run(context.Context, Schedule) error
}

type ScheduleStore interface {
	Due(context.Context, time.Time, int) ([]Schedule, error)
	Claim(context.Context, string, string, time.Time, time.Duration) (bool, error)
	Complete(context.Context, string, string, time.Time, error) error
}

type Scheduler struct {
	runner      Runner
	maxParallel int
	now         func() time.Time
}

func NewScheduler(runner Runner, maxParallel int) (*Scheduler, error) {
	if runner == nil {
		return nil, fmt.Errorf("%w: runner is required", ErrInvalidSchedule)
	}
	if maxParallel < 1 || maxParallel > 64 {
		return nil, fmt.Errorf("%w: max parallel must be between 1 and 64", ErrInvalidSchedule)
	}
	return &Scheduler{runner: runner, maxParallel: maxParallel, now: time.Now}, nil
}

func ValidateSchedule(schedule Schedule) error {
	if schedule.ID == "" || schedule.TenantID == "" || schedule.Target == "" {
		return fmt.Errorf("%w: id, tenant_id and target are required", ErrInvalidSchedule)
	}
	if schedule.Interval < time.Minute || schedule.Interval > 30*24*time.Hour {
		return fmt.Errorf("%w: interval must be between one minute and thirty days", ErrInvalidSchedule)
	}
	if schedule.NextRun.IsZero() {
		return fmt.Errorf("%w: next_run is required", ErrInvalidSchedule)
	}
	return nil
}

func (scheduler *Scheduler) RunDue(ctx context.Context, schedules []Schedule) []RunResult {
	now := scheduler.now().UTC()
	due := make([]Schedule, 0, len(schedules))
	for _, schedule := range schedules {
		if !schedule.Enabled || schedule.NextRun.After(now) {
			continue
		}
		if err := ValidateSchedule(schedule); err != nil {
			continue
		}
		due = append(due, schedule)
	}
	sort.Slice(due, func(left, right int) bool {
		if due[left].NextRun.Equal(due[right].NextRun) {
			return due[left].ID < due[right].ID
		}
		return due[left].NextRun.Before(due[right].NextRun)
	})

	results := make([]RunResult, 0, len(due))
	var mutex sync.Mutex
	semaphore := make(chan struct{}, scheduler.maxParallel)
	var waitGroup sync.WaitGroup
	for _, schedule := range due {
		current := schedule
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			select {
			case semaphore <- struct{}{}:
			case <-ctx.Done():
				mutex.Lock()
				results = append(results, RunResult{ScheduleID: current.ID, Target: current.Target, Err: ctx.Err()})
				mutex.Unlock()
				return
			}
			defer func() { <-semaphore }()

			started := scheduler.now().UTC()
			err := scheduler.runner.Run(ctx, current)
			finished := scheduler.now().UTC()
			mutex.Lock()
			results = append(results, RunResult{ScheduleID: current.ID, Target: current.Target, StartedAt: started, FinishedAt: finished, Err: err})
			mutex.Unlock()
		}()
	}
	waitGroup.Wait()
	sort.Slice(results, func(left, right int) bool { return results[left].ScheduleID < results[right].ScheduleID })
	return results
}

func (scheduler *Scheduler) RunDueFromStore(ctx context.Context, store ScheduleStore, workerID string, now time.Time, lease time.Duration, limit int) ([]RunResult, error) {
	if store == nil || workerID == "" || lease <= 0 || limit < 1 {
		return nil, fmt.Errorf("%w: store, worker ID, lease and limit are required", ErrInvalidSchedule)
	}
	schedules, err := store.Due(ctx, now, limit)
	if err != nil {
		return nil, fmt.Errorf("load due schedules: %w", err)
	}
	claimed := make([]Schedule, 0, len(schedules))
	for _, schedule := range schedules {
		ok, err := store.Claim(ctx, schedule.ID, workerID, now, lease)
		if err != nil {
			return nil, fmt.Errorf("claim schedule %q: %w", schedule.ID, err)
		}
		if ok {
			claimed = append(claimed, schedule)
		}
	}
	results := scheduler.RunDue(ctx, claimed)
	for _, result := range results {
		nextRun := now.Add(time.Minute)
		for _, schedule := range claimed {
			if schedule.ID == result.ScheduleID {
				nextRun = schedule.NextRun.Add(schedule.Interval)
				break
			}
		}
		if err := store.Complete(ctx, result.ScheduleID, workerID, nextRun, result.Err); err != nil {
			return results, fmt.Errorf("complete schedule %q: %w", result.ScheduleID, err)
		}
	}
	return results, nil
}
