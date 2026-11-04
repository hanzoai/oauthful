package oauthful

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type errorFlow struct{}

func (errorFlow) Decode(req *http.Request) (*AuthorizationResponse, error) {
	return &AuthorizationResponse{}, nil
}
func (errorFlow) Verify(res *AuthorizationResponse) error { return nil }
func (errorFlow) AddParams(vals *url.Values) error        { return nil }

// A failing transport must surface its error, not panic: the deferred
// res.Body.Close() used to register before the error check, dereferencing
// the nil *http.Response that Do returns alongside an error.
func TestHandleReturnsTransportError(t *testing.T) {
	boom := errors.New("connection refused")
	client := New(&http.Client{
		Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			return nil, boom
		}),
	}, "http://127.0.0.1:0/token", errorFlow{})

	_, err := client.Handle(&http.Request{})
	if err == nil {
		t.Fatal("expected the transport error, got nil")
	}
	if !strings.Contains(err.Error(), boom.Error()) {
		t.Fatalf("expected the transport error, got %v", err)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
