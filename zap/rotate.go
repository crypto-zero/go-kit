package zap

import (
	"sync/atomic"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	// secondsOfDay is the number of seconds in a day.
	secondsOfDay = 86400
)

// getUnixDays returns the number of days since Unix epoch.
func getUnixDays(t time.Time) uint32 {
	return uint32(t.Unix() / secondsOfDay)
}

// dailyRotateWriter is a writer that rotates the log file daily.
type dailyRotateWriter struct {
	n uint32
	*lumberjack.Logger
}

// newDailyRotateWriter creates a new dailyRotateWriter.
func newDailyRotateWriter(logger *lumberjack.Logger) *dailyRotateWriter {
	return &dailyRotateWriter{
		n:      getUnixDays(time.Now()),
		Logger: logger,
	}
}

func (w *dailyRotateWriter) Write(p []byte) (n int, err error) {
	now := atomic.LoadUint32(&w.n)
	t := getUnixDays(time.Now())
	if t > now && atomic.CompareAndSwapUint32(&w.n, now, t) {
		if err = w.Logger.Rotate(); err != nil {
			return 0, err
		}
	}
	return w.Logger.Write(p)
}
