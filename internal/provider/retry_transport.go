package provider

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// RetryTransport wraps an http.RoundTripper with retry logic for rate limiting and server errors
type RetryTransport struct {
	Transport http.RoundTripper
}

// NewRetryTransport creates a new RetryTransport with the provided base transport
func NewRetryTransport(transport http.RoundTripper) *RetryTransport {
	return &RetryTransport{
		Transport: transport,
	}
}

// RoundTrip implements http.RoundTripper with retry logic
func (rt *RetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	ctx := req.Context()

	operation := func() (*http.Response, error) {
		clonedReq, err := rt.cloneRequest(req)
		if err != nil {
			return nil, backoff.Permanent(fmt.Errorf("failed to clone request: %w", err))
		}

		resp, err := rt.Transport.RoundTrip(clonedReq)
		if err != nil {
			return resp, err
		}

		if rt.shouldRetry(resp.StatusCode) {
			if resp.Body != nil {
				resp.Body.Close()
			}

			tflog.Warn(ctx, "HTTP request returned retryable status code", map[string]any{
				"status_code": resp.StatusCode,
				"url":         req.URL.String(),
				"method":      req.Method,
			})

			return resp, fmt.Errorf("retryable HTTP status code: %d", resp.StatusCode)
		}

		return resp, err
	}

	bExponential := backoff.NewExponentialBackOff()
	bExponential.MaxInterval = 1 * time.Minute
	bExponential.InitialInterval = 2 * time.Second

	bNotify := func(err error, duration time.Duration) {
		tflog.Warn(ctx, "Retrying HTTP request after error", map[string]any{
			"error":         err.Error(),
			"wait_duration": duration.String(),
			"url":           req.URL.String(),
			"method":        req.Method,
		})
	}

	resp, err := backoff.Retry(ctx, operation, backoff.WithBackOff(bExponential), backoff.WithMaxTries(10), backoff.WithNotify(backoff.Notify(bNotify)))

	if err != nil {
		tflog.Error(ctx, "HTTP request failed after all retries", map[string]any{
			"url":    req.URL.String(),
			"method": req.Method,
			"error":  err.Error(),
		})
		return resp, err
	}

	return resp, nil
}

// shouldRetry determines if a status code should trigger a retry
func (rt *RetryTransport) shouldRetry(statusCode int) bool {
	switch statusCode {
	case 429:
		return true
	case 500:
		return true
	case 502:
		return true
	case 503:
		return true
	case 504:
		return true
	default:
		return false
	}
}

// cloneRequest creates a copy of the HTTP request for retry attempts
func (rt *RetryTransport) cloneRequest(req *http.Request) (*http.Request, error) {
	clonedReq := req.Clone(req.Context())

	if req.Body != nil && req.Body != http.NoBody {
		if req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("failed to get request body: %w", err)
			}
			clonedReq.Body = body
		} else {
			bodyBytes, err := io.ReadAll(req.Body)
			if err != nil {
				return nil, fmt.Errorf("failed to read request body: %w", err)
			}

			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

			clonedReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}

	return clonedReq, nil
}

// NewRetryTransportDecorator creates a transport decorator that adds retry logic
func NewRetryTransportDecorator() func(http.RoundTripper) http.RoundTripper {
	return func(transport http.RoundTripper) http.RoundTripper {
		return NewRetryTransport(transport)
	}
}
