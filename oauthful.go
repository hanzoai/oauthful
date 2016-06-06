package oauthful

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

type Client struct {
	// REQUIRED.  Http Client Instance
	HttpClient *http.Client

	// REQUIRED. Url to make the oauth requests to
	Url string

	// REQUIRED, if the "redirect_uri" parameter was included in the
	// authorization request as described in Section 4.1.1, and their
	// values MUST be identical.
	RedirectUri string

	// REQUIRED. Decode Request to Struct
	Decode func(req http.Request) (AuthorizationResponse, error)

	// OPTIONALLY. Do a security check (res.State)
	Verify func(res AuthorizationResponse) error

	// REQUIRED. Add additional parameters to the OAuth Requests (id's and secret parameters)
	AddSecrets func(*url.Values) error

	// REQUIRED. Do something with the results
	Done func(res AccessTokenResponse) error
}

func (c Client) Handle(req http.Request) error {
	if c.Decode == nil {
		return DecodeFunctionRequired
	}

	authRes, err := c.Decode(req)
	if err != nil {
		return err
	}

	if c.Verify != nil {
		if err := c.Verify(authRes); err != nil {
			return err
		}
	}

	// Create the data values
	data := url.Values{}
	data.Add("code", authRes.Code)
	data.Add("grant_type", "authorization_code")
	if c.RedirectUri != "" {
		data.Add("redirect_uri", c.RedirectUri)
	}

	// Add secrets to data values
	if c.AddSecrets == nil {
		return AddSecretsFunctionRequired
	}

	err = c.AddSecrets(&data)
	if err != nil {
		return err
	}

	// Create Authorization Code Request
	tokenReq, err := http.NewRequest("POST", c.Url, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	// Issue Authorization Code Request
	res, err := c.HttpClient.Do(tokenReq)
	defer res.Body.Close()
	if err != nil {
		return err
	}

	// Unmarshal JSON
	tokenRes := AccessTokenResponse{}

	content, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	err = json.Unmarshal(content, &tokenRes)

	if err != nil {
		return err
	}

	// OAuth API returned an error
	if tokenRes.Error != "" {
		return errors.New(tokenRes.Error + "\n" + tokenRes.ErrorDescription + "\n" + tokenRes.ErrorUri)
	}

	if c.Done == nil {
		return DoneFunctionRequired
	}

	return c.Done(tokenRes)
}
