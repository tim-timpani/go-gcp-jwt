package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	defaultMinTokenLifetime = 30
	defaultMaxTokenLifetime = 3600
)

type GcpTokenGenerator struct {
	header             *ClaimHeader
	payload            *ClaimBody
	key                *rsa.PrivateKey
	token              string
	MaxLifetimeSeconds uint64
	MinLifetimeSeconds uint64
}

// GetJWTFromServiceFile - main convenience function to generate a new JWT
func NewGcpTokenGenerator(fileName string, audienceUrl string) (*GcpTokenGenerator, error) {
	var err error
	var sa *GcpServiceAccount
	g := &GcpTokenGenerator{
		MaxLifetimeSeconds: defaultMaxTokenLifetime,
		MinLifetimeSeconds: defaultMinTokenLifetime,
	}

	if sa, err = NewServiceAccount(fileName); err != nil {
		return nil, err
	}

	g.header = &ClaimHeader{
		Alg: "RS256",
		Typ: "JWT",
		Kid: sa.PrivateKeyId,
	}

	g.payload = &ClaimBody{
		Iss: sa.ClientEmail,
		Sub: sa.ClientEmail,
		Aud: audienceUrl,
	}

	if g.key, err = sa.getPrivateKey(); err != nil {
		return nil, err
	}

	return g, nil
}

func (g *GcpTokenGenerator) GetToken() (string, error) {
	if !g.tokenOk() {
		if err := g.refreshToken(); err != nil {
			return "", err
		}
	}
	return g.token, nil
}

func (g *GcpTokenGenerator) tokenOk() bool {
	if g.token == "" {
		return false
	}
	if g.payload.Exp-uint64(time.Now().Unix()) < g.MinLifetimeSeconds {
		return false
	}
	return true
}

func (g *GcpTokenGenerator) refreshToken() error {
	var err error
	var encodedHeader string
	var encodedPayload string
	var sig []byte

	now := uint64(time.Now().Unix())
	g.payload.Iat = now
	g.payload.Exp = now + g.MaxLifetimeSeconds

	if encodedHeader, err = encodeStruct(g.header); err != nil {
		return err
	}
	if encodedPayload, err = encodeStruct(g.payload); err != nil {
		return err
	}

	// sign the hash with the private key
	claim := encodedHeader + "." + encodedPayload
	hashedClaim := sha256.Sum256([]byte(claim))

	if sig, err = g.key.Sign(rand.Reader, hashedClaim[:], crypto.SHA256); err != nil {
		log.Errorf("failed to sign token: %v", err)
		return err
	}

	// append the base64 encoded signature to the claim to complete the JWT
	g.token = claim + "." + base64.StdEncoding.EncodeToString(sig)

	return nil

}

type GcpServiceAccount struct {
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
}

// NewServiceAccount - create a new service account struct from the service file
func NewServiceAccount(fileName string) (g *GcpServiceAccount, err error) {

	var data []byte
	if data, err = os.ReadFile(fileName); err != nil {
		log.Errorf("failed to read service file '%s': %v", fileName, err)
		return
	}

	g = &GcpServiceAccount{}
	if err = json.Unmarshal(data, g); err != nil {
		log.Errorf("failed to unmarshal json from '%s': %v", fileName, err)
	}
	return
}

/*
// NewJWT - main struct method to generate the JWT:  audienceUrl should be set to the base URL for API calls or
// the value of 'x-google-audience' if specified in the OpenAPI document.
func (g *GcpServiceAccount) NewJWT(audienceUrl string, expiry time.Duration) (token string, err error) {

	var body string
	var header string
	var key *rsa.PrivateKey
	var sig []byte

	// construct the JWT token header
	if header, err = encodeStruct(ClaimHeader{
		Alg: "RS256",
		Typ: "JWT",
		Kid: g.PrivateKeyId,
	}); err != nil {
		log.Errorf("failed to create base64-encoded JSON from the JWT header: %v", err)
		return
	}

	// construct the JWT token body
	now := time.Now().Unix()
	if body, err = encodeStruct(ClaimBody{
		Iss: g.ClientEmail,
		Sub: g.ClientEmail,
		Aud: audienceUrl,
		Iat: now,
		Exp: now + int64(expiry.Seconds()),
	}); err != nil {
		log.Errorf("failed to create base64-encoded JSON from the JWT payload: %v", err)
		return
	}

	// create a hash of the claim
	claim := header + "." + body
	hashedClaim := sha256.Sum256([]byte(claim))

	// sign the hash with the private key
	if key, err = g.getPrivateKey(); err != nil {
		return
	}
	if sig, err = key.Sign(rand.Reader, hashedClaim[:], crypto.SHA256); err != nil {
		log.Errorf("failed to sign token: %v", err)
		return
	}

	// append the base64 encoded signature to the claim to complete the JWT
	token = claim + "." + base64.StdEncoding.EncodeToString(sig)

	return
}
*/

// getPrivateKey - create the *rsa.PrivateKey reference from the pem
func (g *GcpServiceAccount) getPrivateKey() (key *rsa.PrivateKey, err error) {
	var ok bool

	// use pem to decode the base64 private key from the service account
	block, _ := pem.Decode([]byte(g.PrivateKey))

	// extract the key
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Errorf("private key parse error: %v", err)
		return
	}

	// verify the type is a private key
	if key, ok = parsedKey.(*rsa.PrivateKey); !ok {
		err = errors.New("private key failed rsa.PrivateKey type assertion")
		log.Error(err)
		return
	}

	return
}

// GetJWTFromServiceFile - main convenience function to generate a new JWT
func GetJWTFromServiceFile(fileName string, audienceUrl string) (jwt string, err error) {
	var gen *GcpTokenGenerator
	if gen, err = NewGcpTokenGenerator(fileName, audienceUrl); err != nil {
		return
	}
	return gen.GetToken()
}

type ClaimHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

type ClaimBody struct {
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Aud string `json:"aud"`
	Exp uint64 `json:"exp"`
	Iat uint64 `json:"iat"`
}

// encodeStruct - returns base64 JSON of exported struct fields with JSON tags
func encodeStruct(s interface{}) (text string, err error) {
	var data []byte
	if data, err = json.Marshal(&s); err != nil {
		return
	}
	text = base64.StdEncoding.EncodeToString(data)
	return
}
