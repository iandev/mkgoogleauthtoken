package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2/jws"
)

const GoogleJwtAudience = "https://www.googleapis.com/oauth2/v4/token"
const GoogleOauth2TokenUrl = "https://www.googleapis.com/oauth2/v4/token"
const GoogleJwtGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

type JWTBearerToken struct {
	token      string
	expiration time.Time
}

func (jbt *JWTBearerToken) Token() string {
	return jbt.token
}

func (jbt *JWTBearerToken) Expiration() time.Time {
	return jbt.expiration
}

func NewJWTBearerToken(token string, expiration time.Time) *JWTBearerToken {
	return &JWTBearerToken{token: token, expiration: expiration}
}

type serviceAccountResponse struct {
	Token            string `json:"id_token"`
	Err              string `json:"error"`
	ErrorDescription string `json:"error_description"`
	Expiration       time.Time
}

func (sar *serviceAccountResponse) Parse() (token *JWTBearerToken, err error) {
	token = NewJWTBearerToken(sar.Token, sar.Expiration)
	if sar.Err != "" || sar.ErrorDescription != "" {
		err = errors.New(fmt.Sprintf("type: %s, msg: %s", sar.Err, sar.ErrorDescription))
	}
	return
}

type JWTTokenProvider interface {
	GetToken(expiresIn time.Duration, claims map[string]interface{}) (token *JWTBearerToken, err error)
}

type GoogleServiceAccountJWT struct {
	Type                    string `json:"type"`
	ProjectId               string `json:"project_id"`
	PrivateKeyId            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"`
	ClientEmail             string `json:"client_email"`
	ClientId                string `json:"client_id"`
	AuthUri                 string `json:"auth_uri"`
	TokenUri                string `json:"token_uri"`
	AuthProviderX509CertUrl string `json:"auth_provider_x509_cert_url"`
	ClientX509CertUrl       string `json:"client_x509_cert_url"`
	parsedKey               *rsa.PrivateKey
}

func MakeJWTTokenFromServiceAccountJSON(JSON string) (*GoogleServiceAccountJWT, error) {
	sa := &GoogleServiceAccountJWT{}
	if err := json.Unmarshal([]byte(JSON), sa); err != nil {
		return nil, err
	}
	return sa, nil
}

func (g *GoogleServiceAccountJWT) GetToken(expiresIn time.Duration, claims map[string]interface{}) (token *JWTBearerToken, err error) {
	expiration := time.Now().Add(expiresIn)
	rsaKey, err := g.getKey()
	if err != nil {
		return
	}
	header := &jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
	}
	var msg string
	if msg, err = jws.Encode(header, g.makeClaim(expiration, claims), rsaKey); err != nil {
		return
	}
	var data []byte
	if data, err = g.requestToken(msg); err != nil {
		return
	}
	tokenData := &serviceAccountResponse{Expiration: expiration}
	if err = json.Unmarshal(data, tokenData); err != nil {
		return
	}
	return tokenData.Parse()
}

func (g *GoogleServiceAccountJWT) requestToken(msg string) ([]byte, error) {
	response, err := http.PostForm(GoogleOauth2TokenUrl, url.Values{
		"grant_type": {GoogleJwtGrantType},
		"assertion":  {msg}},
	)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	return ioutil.ReadAll(response.Body)
}

func (g *GoogleServiceAccountJWT) makeClaim(expiration time.Time, claims map[string]interface{}) *jws.ClaimSet {
	jwt := &jws.ClaimSet{
		Iss:           g.ClientEmail,
		Aud:           GoogleJwtAudience,
		Iat:           time.Now().Unix(),
		Exp:           expiration.Unix(),
		PrivateClaims: claims,
	}
	return jwt
}

func (g *GoogleServiceAccountJWT) getKey() (*rsa.PrivateKey, error) {
	if g.parsedKey != nil {
		return g.parsedKey, nil
	}
	key := []byte(g.PrivateKey)
	block, _ := pem.Decode(key)
	if block != nil {
		key = block.Bytes
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("private key should be a PEM or PKCS8; parse error: %v", err)

	}
	parsedKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is invalid")
	}
	g.parsedKey = parsedKey.(*rsa.PrivateKey)
	return g.parsedKey, nil
}

type PrivateKeyJwt struct {
	PrivateKey string
	parsedKey  *rsa.PrivateKey
}

func MakePrivateKeyJwt(privateKey string) *PrivateKeyJwt {
	return &PrivateKeyJwt{
		PrivateKey: privateKey,
	}
}

func (pkj *PrivateKeyJwt) getKey() (*rsa.PrivateKey, error) {
	if pkj.parsedKey != nil {
		return pkj.parsedKey, nil
	}
	keyBytes := []byte(pkj.PrivateKey)
	return jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
}

func (pkj *PrivateKeyJwt) IsaToken() (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.StandardClaims{IssuedAt: time.Now().Unix()})
	rsaKey, err := pkj.getKey()
	if err != nil {
		return "", err
	}
	return token.SignedString(rsaKey)
}
