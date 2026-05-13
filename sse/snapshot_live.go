package sse

import "context"

// SnapshotLiveOptions configures StreamSnapshotThenLive.
type SnapshotLiveOptions[T any] struct {
	SnapshotEvent    string
	SnapshotEndEvent string
	SnapshotEndData  string
	LiveEvent        string
	ID               func(T) string
	Data             func(T) (any, error)
}

// StreamSnapshotThenLive writes an initial snapshot batch, an optional
// snapshot-end marker, then live events from ch until ctx is canceled or ch
// closes.
func StreamSnapshotThenLive[T any](
	ctx context.Context,
	st *Stream,
	snapshot []T,
	ch <-chan T,
	opts SnapshotLiveOptions[T],
) error {
	for _, item := range snapshot {
		if err := writeSnapshotLiveEvent(st, opts.SnapshotEvent, item, opts); err != nil {
			return err
		}
	}

	if opts.SnapshotEndEvent != "" {
		data := opts.SnapshotEndData
		if data == "" {
			data = "{}"
		}
		if err := st.WriteEvent(Event{Event: opts.SnapshotEndEvent, Data: data}); err != nil {
			return err
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case item, ok := <-ch:
			if !ok {
				return nil
			}
			if err := writeSnapshotLiveEvent(st, opts.LiveEvent, item, opts); err != nil {
				return err
			}
		}
	}
}

func writeSnapshotLiveEvent[T any](st *Stream, event string, item T, opts SnapshotLiveOptions[T]) error {
	id := ""
	if opts.ID != nil {
		id = opts.ID(item)
	}
	if opts.Data == nil {
		return st.WriteJSONEvent(Event{Event: event, ID: id}, item)
	}
	data, err := opts.Data(item)
	if err != nil {
		return err
	}
	if s, ok := data.(string); ok {
		return st.WriteEvent(Event{Event: event, ID: id, Data: s})
	}
	return st.WriteJSONEvent(Event{Event: event, ID: id}, data)
}
