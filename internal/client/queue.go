package client

import (
	"context"
	"fmt"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/syncutil"
)

// queue is a type-safe data structure that allows deduplicating concurrent
// operations.
//
// TODO(e.burkov):  Add tests.
//
// TODO(e.burkov):  Consider moving to golibs.
type queue[K comparable, V any] syncutil.Map[K, *queueResult[V]]

// queueResult is a result of a queued operation.
type queueResult[T any] struct {
	done chan unit
	res  T
	err  error
}

// newQueue creates a new queue.
func newQueue[K comparable, V any]() (q *queue[K, V]) {
	return (*queue[K, V])(syncutil.NewMap[K, *queueResult[V]]())
}

// push queues an operation for the given key.  If there is already an operation
// in progress for the key, it waits for it to complete and returns its result.
// Otherwise, it returns a zero value and nil error, and the caller must
// eventually call [queue.done] to complete the operation and broadcast the
// result to other callers.
func (q *queue[K, V]) push(ctx context.Context, key K) (res V, err error) {
	m := (*syncutil.Map[K, *queueResult[V]])(q)
	queueRes := &queueResult[V]{
		done: make(chan unit),
	}

	queueRes, loaded := m.LoadOrStore(key, queueRes)
	if loaded {
		select {
		case <-queueRes.done:
			return queueRes.res, queueRes.err
		case <-ctx.Done():
			return res, ctx.Err()
		}
	}

	return res, nil
}

// done completes the operation for the given key and broadcasts the result to
// other callers.  It must be called exactly once for each call to [queue.push]
// ending with a zero value and nil error.
func (q *queue[K, V]) done(key K, res V, err error) {
	m := (*syncutil.Map[K, *queueResult[V]])(q)

	queueRes, ok := m.Load(key)
	if !ok {
		panic(fmt.Errorf("queued result for %v: %w", key, errors.ErrNoValue))
	}

	queueRes.res, queueRes.err = res, err

	close(queueRes.done)
	m.Delete(key)
}
