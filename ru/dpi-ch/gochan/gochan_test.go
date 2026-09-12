package gochan

import (
	"context"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestStartProcessesAllItemsAndRunsPost(t *testing.T) {
	ctx := context.Background()
	input := make(chan int, 5)
	for i := 1; i <= 5; i++ {
		input <- i
	}
	close(input)

	var postCalled atomic.Bool
	out := Start(GochanOpt[int, int]{
		Ctx:     ctx,
		Workers: 2,
		Input:   input,
		Executor: func(v int) int {
			return v * 2
		},
		Post: func() {
			postCalled.Store(true)
		},
	})

	got := []int{}
	for v := range out {
		got = append(got, v)
	}
	slices.Sort(got)

	if !slices.Equal(got, []int{2, 4, 6, 8, 10}) {
		t.Fatalf("got %v, want [2 4 6 8 10]", got)
	}
	if !postCalled.Load() {
		t.Fatal("post callback was not called")
	}
}

func TestStartWithCancelledContextClosesOutput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	input := make(chan int)
	out := Start(GochanOpt[int, int]{
		Ctx:      ctx,
		Workers:  2,
		Input:    input,
		Executor: func(v int) int { return v },
	})

	select {
	case _, ok := <-out:
		if ok {
			t.Fatal("got an output after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("output channel did not close after cancellation")
	}
}

func TestStartCancellationClosesOutputWhileWorkerIsBlockedOnSend(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	input := make(chan int, 1)
	input <- 1
	close(input)

	var executed atomic.Int32
	out := Start(GochanOpt[int, int]{
		Ctx:     ctx,
		Workers: 1,
		Input:   input,
		Executor: func(v int) int {
			executed.Add(1)
			return v
		},
	})

	deadline := time.After(time.Second)
	for executed.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("executor did not run")
		default:
			time.Sleep(time.Millisecond)
		}
	}

	cancel()
	select {
	case _, ok := <-out:
		if ok {
			t.Fatal("got an output after cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("output channel did not close after cancellation")
	}
}

func TestStartCancellationClosesOutputWhileInputIsBlocked(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	input := make(chan int)
	out := Start(GochanOpt[int, int]{
		Ctx:      ctx,
		Workers:  1,
		Input:    input,
		Executor: func(v int) int { return v },
	})

	cancel()
	select {
	case _, ok := <-out:
		if ok {
			t.Fatal("got an output while input was blocked")
		}
	case <-time.After(time.Second):
		t.Fatal("output channel did not close after cancellation")
	}
}

func TestStartZeroWorkersRunsPostAndClosesOutput(t *testing.T) {
	called := false
	input := make(chan int)
	out := Start(GochanOpt[int, int]{
		Ctx:      context.Background(),
		Workers:  0,
		Input:    input,
		Executor: func(v int) int { return v },
		Post: func() {
			called = true
		},
	})

	if _, ok := <-out; ok {
		t.Fatal("zero-worker output channel produced a value")
	}
	if !called {
		t.Fatal("post callback was not called for zero workers")
	}
}

func TestPushPreservesOrderAndClosesChannel(t *testing.T) {
	ctx := context.Background()
	ch := make(chan int)
	Push(ctx, ch, []int{1, 2, 3, 4})

	var got []int
	for v := range ch {
		got = append(got, v)
	}
	if !slices.Equal(got, []int{1, 2, 3, 4}) {
		t.Fatalf("got %v, want [1 2 3 4]", got)
	}
}

func TestRepeatProducesRequestedCount(t *testing.T) {
	ctx := context.Background()
	ch := make(chan string)
	Repeat(ctx, ch, "x", 4)

	count := 0
	for v := range ch {
		if v != "x" {
			t.Fatalf("got %q, want %q", v, "x")
		}
		count++
	}
	if count != 4 {
		t.Fatalf("got %d items, want 4", count)
	}
}

func TestRepeatWithNonPositiveCountIsEmpty(t *testing.T) {
	for _, n := range []int{0, -1} {
		t.Run("count "+strconv.Itoa(n), func(t *testing.T) {
			ch := make(chan int)
			Repeat(context.Background(), ch, 1, n)
			if _, ok := <-ch; ok {
				t.Fatalf("Repeat(%d) produced a value", n)
			}
		})
	}
}

func TestClosedReturnsClosedChannel(t *testing.T) {
	ch := Closed[int]()
	if _, ok := <-ch; ok {
		t.Fatal("Closed returned an open channel")
	}
}
