package oauthful

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

func New(httpClient *http.Client, url string, flow OAuthFlow) *Client {
	return &Client{
		httpClient,
		url,
		flow,
	}
}

type OAuthFlow interface {
	// Decode Request to Struct
	Decode(req *http.Request) (*AuthorizationResponse, error)

	// Do a security check (usually involves res.State parameter passed by Authorization Request)
	Verify(res *AuthorizationResponse) error

	// Add additional parameters to the OAuth Requests (client_id, client_secret, request_uri, etc)
	AddParams(vals *url.Values) error
}

type Client struct {
	// Http Client Instance
	HttpClient *http.Client

	// Url to make the oauth requests to
	Url string

	// Flow for the OAuth data
	Flow OAuthFlow
}

func (c Client) Handle(req *http.Request) (*AccessTokenResponse, error) {
	if c.Flow == nil {
		return nil, FlowRequired
	}

	authRes, err := c.Flow.Decode(req)
	if err != nil {
		return nil, err
	}

	err = c.Flow.Verify(authRes)
	if err != nil {
		return nil, err
	}

	// Create the data values
	data := url.Values{}
	data.Add("code", authRes.Code)
	data.Add("grant_type", "authorization_code")

	// Add secrets to data values
	err = c.Flow.AddParams(&data)
	if err != nil {
		return nil, err
	}

	// Create Authorization Code Request
	tokenReq, err := http.NewRequest("POST", c.Url, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}

	// Issue Authorization Code Request
	res, err := c.HttpClient.Do(tokenReq)
	defer res.Body.Close()
	if err != nil {
		return nil, err
	}

	// Unmarshal JSON
	tokenRes := &AccessTokenResponse{}

	content, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(content, &tokenRes)

	if err != nil {
		return nil, err
	}

	// OAuth API returned an error
	if tokenRes.Error != "" {
		return nil, errors.New(tokenRes.Error + "\n" + tokenRes.ErrorDescription + "\n" + tokenRes.ErrorUri)
	}

	return tokenRes, nil
}
