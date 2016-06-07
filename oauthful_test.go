package oauthful

import (
	"flag"
	"net/http"
	"net/url"
	"os"
	"testing"
)

type TestFlow struct {
}

func (t TestFlow) Decode(req http.Request) (AuthorizationResponse, error) {
	return AuthorizationResponse{}, nil
}

func (t TestFlow) Verify(res AuthorizationResponse) error {
	return nil
}

func (t TestFlow) AddParams(vals *url.Values) error {
	return nil
}

func (t TestFlow) Done(res AccessTokenResponse) error {
	return nil
}

func TestMain(m *testing.M) {
	var err error

	if err != nil {
		panic(err)
	}
	flag.Parse()
	os.Exit(m.Run())
}

func CreateClient() {
	_ = New(&http.Client{}, "localhost", TestFlow{})
}
