package oauthful

import "errors"

var DecodeFunctionRequired = errors.New("Provide a Decode Function")
var AddSecretsFunctionRequired = errors.New("Provide an AddSecrets Function")
var DoneFunctionRequired = errors.New("Provide a Done Function")
