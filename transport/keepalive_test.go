package transport

import (
	"testing"
	"time"
)

func TestKeepAliveBudgets(t *testing.T) {
	if KeepAliveInterval <= 0 || KeepAliveTimeout <= 0 || MaxIdleTimeout <= 0 {
		t.Fatal("keepalive budgets must be positive")
	}
	// Several probes must fit under the dead-peer timeout so a single lost
	// keepalive on a lossy path does not drop the session.
	if KeepAliveTimeout < 3*KeepAliveInterval {
		t.Fatalf("KeepAliveTimeout %v too tight for interval %v", KeepAliveTimeout, KeepAliveInterval)
	}
	if MaxIdleTimeout < KeepAliveTimeout {
		t.Fatalf("MaxIdleTimeout %v < KeepAliveTimeout %v", MaxIdleTimeout, KeepAliveTimeout)
	}
	// Stay under the common ~30s middlebox idle floor with margin.
	if KeepAliveInterval >= 30*time.Second {
		t.Fatalf("KeepAliveInterval %v must stay under typical 30s NAT idle", KeepAliveInterval)
	}
	if KeepAliveInterval >= PingTimeout {
		t.Fatalf("PingTimeout %v should exceed KeepAliveInterval %v", PingTimeout, KeepAliveInterval)
	}
}
