package oauthful

import "errors"

var (
	FlowRequired = errors.New("Provide a OAuth Flow")
)
