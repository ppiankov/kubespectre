package k8s

import (
	"context"
	"strings"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
)

// WO-48: retry bounds are fixed and small -- a retrying call must never itself
// exhaust the operator's --timeout on a healthy but momentarily blipping
// cluster. Motivated by an empirically observed, recurring failure: a single
// transient network stream-reset on a List call silently zeroed out an
// entire auditor's findings for the run, with no retry at all and no way to
// tell a transient blip from a genuine, permanent failure.
const (
	retryMaxAttempts  = 3
	retryBaseDelay    = 200 * time.Millisecond
	retryMaxTotalWait = 3 * time.Second
)

// WO-48: transientErrorSignatures is a closed, fixed allowlist of network-level
// error text -- an unrecognized error is never guessed to be transient. This
// mirrors NodeScanner's closed condition allowlist (WO-47): absence from the
// allowlist is never treated as a positive (retryable) signal.
var transientErrorSignatures = []string{
	"stream error",
	"INTERNAL_ERROR",
	"unexpected EOF",
	"connection reset by peer",
	"broken pipe",
	"http2: client conn not usable",
	"use of closed network connection",
}

// WO-48: isTransientListError reports whether err is a network-level blip
// worth retrying. Permanent errors (RBAC Forbidden/NotFound/Unauthorized)
// always return false, unchanged from pre-WO-48 fail-immediately behavior. A
// context already past its deadline also returns false -- retrying then
// cannot succeed and would only spend already-exhausted --timeout budget on
// a foregone conclusion.
func isTransientListError(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() != nil {
		return false
	}
	if k8serrors.IsForbidden(err) || k8serrors.IsNotFound(err) || k8serrors.IsUnauthorized(err) {
		return false
	}
	msg := err.Error()
	for _, signature := range transientErrorSignatures {
		if strings.Contains(msg, signature) {
			return true
		}
	}
	return false
}

// WO-48: retryTransient retries fn up to retryMaxAttempts times, but only for
// errors isTransientListError classifies as transient; a permanent error
// returns on the first attempt, identical to pre-WO-48 behavior. Backoff is
// capped at retryMaxTotalWait total across all attempts, so this cannot
// itself cause a --timeout exhaustion on an otherwise healthy cluster.
func retryTransient[T any](ctx context.Context, fn func() (T, error)) (T, error) {
	var zero T
	var lastErr error
	waited := time.Duration(0)
	for attempt := 0; attempt < retryMaxAttempts; attempt++ {
		result, err := fn()
		if err == nil {
			return result, nil
		}
		lastErr = err
		if !isTransientListError(ctx, err) {
			return zero, err
		}
		if attempt == retryMaxAttempts-1 {
			break
		}
		delay := retryBaseDelay * time.Duration(uint(1)<<uint(attempt))
		if waited+delay > retryMaxTotalWait {
			delay = retryMaxTotalWait - waited
		}
		if delay <= 0 {
			break
		}
		select {
		case <-ctx.Done():
			return zero, lastErr
		case <-time.After(delay):
		}
		waited += delay
	}
	return zero, lastErr
}
