package zap

import (
	"sync/atomic"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

// getUnixDays returns the number of days since Unix epoch.
func getUnixDays(t time.Time) uint32 {
	return uint32(t.Unix() / 86400)
}

type DailyRotateWriter struct {
	n uint32
	*lumberjack.Logger
}

// NewDailyRotateWriter creates a new DailyRotateWriter.
func NewDailyRotateWriter(logger *lumberjack.Logger) *DailyRotateWriter {
	return &DailyRotateWriter{
		n:      getUnixDays(time.Now()),
		Logger: logger,
	}
}

func (w *DailyRotateWriter) Write(p []byte) (n int, err error) {
	now := atomic.LoadUint32(&w.n)
	t := getUnixDays(time.Now())
	if t > now && atomic.CompareAndSwapUint32(&w.n, now, t) {
		if err = w.Logger.Rotate(); err != nil {
			return 0, err
		}
	}
	return w.Logger.Write(p)
}
