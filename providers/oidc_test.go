package providers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/bmizerany/assert"
	"github.com/coreos/go-oidc"
	"github.com/dgrijalva/jwt-go"
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"

	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const accessToken = "access_token"
const refreshToken = "refresh_token"
const clientID = "https://test.myapp.com"
const secret = "secret"

type IDTokenClaims struct {
	Name    string `json:"name,omitempty"`
	Email   string `json:"email,omitempty"`
	Picture string `json:"picture,omitempty"`
	jwt.StandardClaims
}
type RedeemResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token,omitempty"`
}

var TestIDToken = IDTokenClaims{
	"Jane Dobbs",
	"janed@me.com",
	"http://mugbook.com/janed/me.jpg",
	jwt.StandardClaims{
		Audience:  "https://test.myapp.com",
		ExpiresAt: time.Now().Add(time.Duration(5) * time.Second).Unix(),
		Id:        "id-some-id",
		IssuedAt:  time.Now().Unix(),
		Issuer:    "https://issuer.example.com",
		NotBefore: 0,
		Subject:   "123456789",
	},
}

type NoOpKeySet struct{}

func (NoOpKeySet) VerifySignature(ctx context.Context, jwt string) (payload []byte, err error) {
	payloadPart := strings.Split(jwt, ".")[1]
	return base64.RawURLEncoding.DecodeString(payloadPart)
}

func newOIDCProvider(serverURL *url.URL) *OIDCProvider {
	providerData := &ProviderData{
		ProviderName: "oidc",
		ClientID:     clientID,
		ClientSecret: secret,
		LoginURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/login/oauth/authorize"},
		RedeemURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/login/oauth/access_token"},
		ProfileURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/profile"},
		ValidateURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/api"},
		Scope: "openid profile offline_access"}

	p := &OIDCProvider{
		ProviderData: providerData,
		Verifier: oidc.NewVerifier(
			"https://issuer.example.com",
			NoOpKeySet{},
			&oidc.Config{ClientID: clientID},
		),
	}

	return p
}

func newOIDCServer(body []byte) (*url.URL, *httptest.Server) {
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Add("content-type", "application/json")
		rw.Write(body)
	}))
	u, _ := url.Parse(s.URL)
	return u, s
}

func getSignedTestIDToken() (string, error) {

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	standardClaims := jwt.NewWithClaims(jwt.SigningMethodRS256, TestIDToken)
	return standardClaims.SignedString(key)
}

func TestOIDCProviderRedeem(t *testing.T) {

	signedIDToken, err := getSignedTestIDToken()
	assert.Equal(t, nil, err)

	body, err := json.Marshal(RedeemResponse{
		AccessToken:  accessToken,
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		IDToken:      signedIDToken,
	})
	assert.Equal(t, nil, err)

	var server *httptest.Server
	redeemURL, server := newOIDCServer(body)
	p := newOIDCProvider(redeemURL)
	defer server.Close()

	session, err := p.Redeem(p.RedeemURL.String(), "code1234")
	assert.Equal(t, nil, err)
	assert.Equal(t, TestIDToken.Email, session.Email)
	assert.Equal(t, accessToken, session.AccessToken)
	assert.Equal(t, signedIDToken, session.IDToken)
	assert.Equal(t, refreshToken, session.RefreshToken)
	assert.Equal(t, "123456789", session.User)
	// Expiry and creation not tested until a clock can be used instead
}

func TestOIDCProviderRefreshSessionIfNeededWithoutIdToken(t *testing.T) {

	signedIDToken, err := getSignedTestIDToken()
	assert.Equal(t, nil, err)

	body, err := json.Marshal(RedeemResponse{
		AccessToken:  accessToken,
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
	})
	assert.Equal(t, nil, err)

	var server *httptest.Server
	redeemURL, server := newOIDCServer(body)
	p := newOIDCProvider(redeemURL)
	defer server.Close()

	existingSession := &sessions.SessionState{
		AccessToken:  "changeit",
		IDToken:      signedIDToken,
		CreatedAt:    time.Time{},
		ExpiresOn:    time.Time{},
		RefreshToken: refreshToken,
		Email:        "janedoe@example.com",
		User:         "123456789",
	}
	refreshed, err := p.RefreshSessionIfNeeded(existingSession)
	assert.Equal(t, nil, err)
	assert.Equal(t, refreshed, true)
	assert.Equal(t, "janedoe@example.com", existingSession.Email)
	assert.Equal(t, accessToken, existingSession.AccessToken)
	assert.Equal(t, signedIDToken, existingSession.IDToken)
	assert.Equal(t, refreshToken, existingSession.RefreshToken)
	assert.Equal(t, "123456789", existingSession.User)
}

func TestOIDCProviderRefreshSessionIfNeededWithIdToken(t *testing.T) {

	signedIDToken, err := getSignedTestIDToken()
	assert.Equal(t, nil, err)

	body, err := json.Marshal(RedeemResponse{
		AccessToken:  accessToken,
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		IDToken:      signedIDToken,
	})
	assert.Equal(t, nil, err)

	var server *httptest.Server
	redeemURL, server := newOIDCServer(body)
	p := newOIDCProvider(redeemURL)
	defer server.Close()

	existingSession := &sessions.SessionState{
		AccessToken:  "changeit",
		IDToken:      "changeit",
		CreatedAt:    time.Time{},
		ExpiresOn:    time.Time{},
		RefreshToken: refreshToken,
		Email:        "janedoe@example.com",
		User:         "123456789",
	}
	refreshed, err := p.RefreshSessionIfNeeded(existingSession)
	assert.Equal(t, nil, err)
	assert.Equal(t, refreshed, true)
	assert.Equal(t, TestIDToken.Email, existingSession.Email)
	assert.Equal(t, accessToken, existingSession.AccessToken)
	assert.Equal(t, signedIDToken, existingSession.IDToken)
	assert.Equal(t, refreshToken, existingSession.RefreshToken)
	assert.Equal(t, "123456789", existingSession.User)
}

func TestOIDCProvider_findVerifiedIdToken(t *testing.T) {

	provider := new(OIDCProvider)

	verifierFn := func(rawIdToken string) (*oidc.IDToken, error) {
		switch {
		case rawIdToken == "some-token":
			return new(oidc.IDToken), nil
		case rawIdToken == "error":
			return nil, fmt.Errorf("kerblam")
		default:
			return nil, nil
		}
	}

	findTokenFn := func(in string) func() (string, bool) {
		return func() (string, bool) {
			return in, len(in) > 0
		}
	}

	token, err := provider.extractIDToken(findTokenFn("some-token"), verifierFn)
	assert.Equal(t, new(oidc.IDToken), token)
	assert.Equal(t, nil, err)

	token, err = provider.extractIDToken(findTokenFn("error"), verifierFn)
	assert.Equal(t, true, token == nil)
	assert.Equal(t, fmt.Errorf("kerblam"), err)

	token, err = provider.extractIDToken(findTokenFn(""), verifierFn)
	assert.Equal(t, true, token == nil)
	assert.Equal(t, nil, err)
}
