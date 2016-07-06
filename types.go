package oauthful

type AccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`

	ErrorResponse
}

type AuthorizationResponse struct {
	AccessTokenResponse

	Code  string `json:"code"`
	State string `json:"state"`
}

// type AccessTokenRequest struct {
// 	GrantType   string `json:"grant_type"`
// 	Code        string `json:"code"`
// 	RedirectURI string `json:"redirect_uri"`
// 	ClientId    string `json:"client_id"`
// }

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorUri         string `json:"error_uri"`
	ErrorDescription string `json:"error_description"`
}
