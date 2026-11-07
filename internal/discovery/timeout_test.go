package discovery

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestProbeServiceHonorsTimeout(t *testing.T) {
	engine := &Engine{
		dialer:  blockingDialer{},
		timeout: 10 * time.Millisecond,
	}

	started := time.Now()
	_, reachable := engine.probeService(context.Background(), "example.com", net.ParseIP("203.0.113.10"), 443)
	elapsed := time.Since(started)

	if reachable {
		t.Fatal("expected timed out service to be unreachable")
	}
	if elapsed > time.Second {
		t.Fatalf("probe exceeded expected timeout bound: %s", elapsed)
	}
}

type blockingDialer struct{}

func (blockingDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
