package device

import (
	"context"
	"math"
	"time"
)

type poller interface {
	GetInterval() time.Duration
	SetInterval(time.Duration)
	Wait(multiplier float64) error
	Cancel()
}

type pollerFactory func(context.Context, time.Duration, time.Duration) (context.Context, poller)

func newPoller(ctx context.Context, checkInterval, expiresIn time.Duration) (context.Context, poller) {
	c, cancel := context.WithTimeout(ctx, expiresIn)
	return c, &intervalPoller{
		ctx:        c,
		interval:   checkInterval,
		cancelFunc: cancel,
	}
}

type intervalPoller struct {
	ctx        context.Context
	interval   time.Duration
	cancelFunc func()
}

func (p *intervalPoller) GetInterval() time.Duration {
	return p.interval
}

func (p *intervalPoller) SetInterval(d time.Duration) {
	p.interval = d
}

func (p *intervalPoller) Wait(multiplier float64) error {
	interval := time.Duration(math.Ceil(float64(p.interval) * multiplier))
	t := time.NewTimer(interval)
	select {
	case <-p.ctx.Done():
		t.Stop()
		return p.ctx.Err()
	case <-t.C:
		return nil
	}
}

func (p *intervalPoller) Cancel() {
	p.cancelFunc()
}
