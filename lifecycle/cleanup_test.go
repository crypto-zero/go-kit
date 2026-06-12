package lifecycle

import (
	"testing"
)

func TestCleanupStackRunsInReverseOrder(t *testing.T) {
	var order []int
	var s CleanupStack
	s.Add(func() { order = append(order, 1) })
	s.Add(nil) // must be skipped, not panic
	s.Add(func() { order = append(order, 2) })
	s.Add(func() { order = append(order, 3) })

	s.Run()

	want := []int{3, 2, 1}
	if len(order) != len(want) {
		t.Fatalf("ran %d cleanups, want %d: %v", len(order), len(want), order)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("cleanup order = %v, want %v (LIFO)", order, want)
		}
	}
}

func TestCleanupStackZeroValueRunIsNoop(t *testing.T) {
	var s CleanupStack
	s.Run() // must not panic on nil funcs
}
