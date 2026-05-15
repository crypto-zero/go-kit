package sse

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
)

// Reader reads Server-Sent Events from an HTTP response body.
type Reader struct {
	r      *bufio.Reader
	c      io.Closer
	lastID string
}

// NewReader returns an SSE event reader for r.
func NewReader(r io.Reader) *Reader {
	er := &Reader{r: bufio.NewReader(r)}
	if c, ok := r.(io.Closer); ok {
		er.c = c
	}
	return er
}

// Next blocks until the next complete event frame is read.
func (r *Reader) Next() (*Event, error) {
	var ev Event
	var data []string
	seen := false
	idSeen := false
	for {
		line, err := r.r.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) && seen {
				return r.finishEvent(ev, data, idSeen), nil
			}
			return nil, err
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if line == "" {
			if !seen {
				continue
			}
			return r.finishEvent(ev, data, idSeen), nil
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		seen = true
		field, value, ok := strings.Cut(line, ":")
		if !ok {
			value = ""
		} else if strings.HasPrefix(value, " ") {
			value = value[1:]
		}
		switch field {
		case "event":
			ev.Event = value
		case "id":
			ev.ID = value
			idSeen = true
		case "data":
			data = append(data, value)
		case "retry":
			if ms, err := strconv.ParseInt(value, 10, 64); err == nil {
				ev.Retry = time.Duration(ms) * time.Millisecond
			}
		}
	}
}

func (r *Reader) finishEvent(ev Event, data []string, idSeen bool) *Event {
	if idSeen {
		r.lastID = ev.ID
	} else {
		ev.ID = r.lastID
	}
	ev.Data = strings.Join(data, "\n")
	return &ev
}

// Close closes the underlying reader when it implements io.Closer.
func (r *Reader) Close() error {
	if r.c == nil {
		return nil
	}
	return r.c.Close()
}
