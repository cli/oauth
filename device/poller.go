package device

import (
	"context"
	"time"
)

type poller interface {
	Wait() error
	Cancel()
}

type pollerFactory func(context.Context, time.Duration, time.Duration) (context.Context, poller)

func newPoller(ctx context.Context, checkInteval, expiresIn time.Duration) (context.Context, poller) {
	c, cancel := context.WithTimeout(ctx, expiresIn)
	return c, &intervalPoller{
		ctx:        c,
		interval:   checkInteval,
		cancelFunc: cancel,
	}
}

type intervalPoller struct {
	ctx        context.Context
	interval   time.Duration
	cancelFunc func()
}

func (p intervalPoller) Wait() error {
	t := time.NewTimer(p.interval)
	select {
	case <-p.ctx.Done():
		t.Stop()
		return p.ctx.Err()
	case <-t.C:
		return nil
	}
}

func (p intervalPoller) Cancel() {
	p.cancelFunc()
}
