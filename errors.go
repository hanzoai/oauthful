package oauthful

import "errors"

var (
	DecodeFunctionRequired    = errors.New("Provide a Decode Function")
	AddParamsFunctionRequired = errors.New("Provide an AddSecrets Function")
	DoneFunctionRequired      = errors.New("Provide a Done Function")
)
