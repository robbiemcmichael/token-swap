package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	dex "github.com/dexidp/dex/storage/kubernetes"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Config struct {
	Token      string                 `json:"token"`
	DexSigner  bool                   `json:"dexSigner"`
	Claims     map[string]interface{} `json:"claims"`
	Issuers    []*Issuer              `json:"issuers"`
	SigningKey jose.SigningKey
	Logger     *log.Logger
}

type Issuer struct {
	Issuer          string      `json:"issuer"`
	PublicKey       string      `json:"publicKey"`
	ParsedPublicKey interface{} // *rsa.PublicKey, *dsa.PublicKey or *ecdsa.PublicKey
	Mappings        []Mapping   `json:"mappings"`
}

type Mapping struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Prefix string `json:"prefix"`
}

type Secrets struct {
	Algorithm  string `json:"algorithm"`
	PrivateKey string `json:"privateKey"`
}

func main() {
	if err := mainE(); err != nil {
		panic(err)
	}
}

func mainE() error {
	viperConfig := viper.New()
	viperConfig.SetConfigName("config")
	viperConfig.AddConfigPath(".")

	err := viperConfig.ReadInConfig()
	if err != nil {
		return fmt.Errorf("failed to read config: %s", err)
	}

	var config Config
	config.Logger = log.New()

	err = viperConfig.Unmarshal(&config)
	if err != nil {
		return fmt.Errorf("failed to unmarshal config: %s", err)
	}

	viperSecrets := viper.New()
	viperSecrets.SetConfigName("secrets")
	viperSecrets.AddConfigPath(".")

	err = viperSecrets.ReadInConfig()
	if err != nil {
		return fmt.Errorf("failed to read secrets: %s", err)
	}

	var secrets Secrets
	err = viperSecrets.Unmarshal(&secrets)
	if err != nil {
		return fmt.Errorf("failed to unmarshal secrets: %s", err)
	}

	if config.DexSigner {
		err = config.loadDexSigningKey()
		if err != nil {
			return fmt.Errorf("failed to load Dex signing key: %s", err)
		}
	} else {
		err = config.loadSigningKey(&secrets)
		if err != nil {
			return fmt.Errorf("failed to load signing key from config: %s", err)
		}
	}

	for _, issuer := range config.Issuers {
		err := issuer.parsePublicKey()
		if err != nil {
			return err
		}
	}

	http.HandleFunc("/", config.handler)
	config.Logger.Fatal(http.ListenAndServe(":8080", nil))

	return nil
}

func (config *Config) loadSigningKey(secrets *Secrets) error {
	block, _ := pem.Decode([]byte(secrets.PrivateKey))
	if block == nil {
		return fmt.Errorf("failed to read PEM block for private key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %s", err)
	}

	jsonWebKey := jose.JSONWebKey{
		Key:          key,
		Certificates: []*x509.Certificate{},
		KeyID:        "token-swap",
		Algorithm:    secrets.Algorithm,
		Use:          "some use",
	}

	config.SigningKey = jose.SigningKey{
		Key:       key,
		Algorithm: jose.SignatureAlgorithm(jsonWebKey.Algorithm),
	}
	return nil
}

func (config *Config) loadDexSigningKey() error {
	dexConfig := dex.Config{
		InCluster: true,
		UseTPR:    false,
	}

	storage, err := dexConfig.Open(config.Logger)
	if err != nil {
		return err
	}

	keys, err := storage.GetKeys()
	if err != nil {
		return err
	}

	config.SigningKey = jose.SigningKey{
		Key:       keys.SigningKey.Key,
		Algorithm: jose.SignatureAlgorithm(keys.SigningKey.Algorithm),
	}

	return nil
}

func (config *Config) validateToken(token string) (map[string]interface{}, error) {
	expectedIssuer, err := getIssuer(token)
	if err != nil {
		return nil, err
	}

	for _, issuer := range config.Issuers {
		if issuer.Issuer == expectedIssuer {
			claims, err := issuer.getClaims(token)
			if err != nil {
				return nil, fmt.Errorf("validation for issuer %s failed: %s", issuer.Issuer, err)
			} else {
				config.Logger.Infof("Validated claims for issuer %s: %+v\n", issuer.Issuer, claims)

				newClaims, err := issuer.mapClaims(claims)
				if err != nil {
					return nil, err
				}

				return newClaims, nil
			}
		}
	}

	return nil, fmt.Errorf("%s is not a valid issuer", expectedIssuer)
}

func (config *Config) issueToken(claims map[string]interface{}) (string, error) {
	signer, err := jose.NewSigner(config.SigningKey, &jose.SignerOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get signer: %s", err)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %s", err)
	}

	signature, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("failed to sign payload: %s", err)
	}

	return signature.CompactSerialize()
}

func (issuer *Issuer) parsePublicKey() error {
	block, _ := pem.Decode([]byte(issuer.PublicKey))
	if block == nil {
		return fmt.Errorf("failed to read PEM block for issuer '%s'", issuer.Issuer)
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key for issuer '%s': %s", issuer.Issuer, err)
	}

	issuer.ParsedPublicKey = key
	return nil
}

func getIssuer(tokenString string) (string, error) {
	token, err := jwt.ParseSigned(tokenString)
	if err != nil {
		return "", err
	}

	var publicClaims jwt.Claims
	if err := token.UnsafeClaimsWithoutVerification(&publicClaims); err != nil {
		return "", fmt.Errorf("failed to get public claims: %s", err)
	}

	return publicClaims.Issuer, nil
}

func (issuer *Issuer) getClaims(tokenString string) (map[string]interface{}, error) {
	if issuer.ParsedPublicKey == nil {
		return nil, fmt.Errorf("public key for issuer '%s' was not parsed", issuer.Issuer)
	}

	token, err := jwt.ParseSigned(tokenString)
	if err != nil {
		return nil, err
	}

	var publicClaims jwt.Claims
	if err := token.Claims(issuer.ParsedPublicKey, &publicClaims); err != nil {
		return nil, fmt.Errorf("failed to get public claims: %s", err)
	}

	expected := jwt.Expected{
		Issuer: issuer.Issuer,
		Time:   time.Now(),
	}
	if err := publicClaims.Validate(expected); err != nil {
		return nil, fmt.Errorf("failed to validate public claims: %s", err)
	}

	var claims interface{}
	if err := token.Claims(issuer.ParsedPublicKey, &claims); err != nil {
		return nil, err
	}

	claimsMap, ok := claims.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("failed to cast claims to map[string]interface{}")
	}

	return claimsMap, nil
}

func (issuer *Issuer) mapClaims(src map[string]interface{}) (map[string]interface{}, error) {
	dest := make(map[string]interface{})
	for _, mapping := range issuer.Mappings {
		if mapping.Prefix != "" {
			claim, err := prefixClaim(mapping.Prefix, src[mapping.From])
			if err != nil {
				return nil, err
			}
			dest[mapping.To] = claim
		} else {
			dest[mapping.To] = src[mapping.From]
		}
	}

	return dest, nil
}

func prefixClaim(prefix string, claim interface{}) (interface{}, error) {
	switch claim.(type) {
	case string:
		return prefix + claim.(string), nil
	case []interface{}:
		array := []string{}
		for _, element := range claim.([]interface{}) {
			elementString, ok := element.(string)
			if ok {
				array = append(array, prefix+elementString)
			} else {
				return nil, fmt.Errorf("claim must be array of strings (%+v)\n", claim)
			}
		}
		return array, nil
	default:
		return nil, fmt.Errorf("claim must be string or array of strings (%+v)\n", claim)
	}
}

func (config *Config) handler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		w.WriteHeader(http.StatusUnauthorized)
		_, err := w.Write([]byte("Bearer token must be set in authorization header\n"))
		if err != nil {
			config.Logger.Errorf("Failed to write error to response body: %s", err)
		}
		return
	}

	token := strings.TrimPrefix(auth, "Bearer ")
	claims, err := config.validateToken(token)
	if err != nil {
		config.Logger.Infof("Rejected token")
		w.WriteHeader(http.StatusForbidden)
		_, err := w.Write([]byte(err.Error() + "\n"))
		if err != nil {
			config.Logger.Errorf("Failed to write error to response body: %s", err)
		}
		return
	}

	signedToken, err := config.issueToken(claims)
	if err != nil {
		config.Logger.Errorf("failed to sign token: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		_, err := w.Write([]byte("Failed to sign token\n"))
		if err != nil {
			config.Logger.Errorf("Failed to write error to response body: %s", err)
		}
		return
	}

	w.WriteHeader(http.StatusOK)
	_, err = w.Write([]byte(signedToken + "\n"))
	if err != nil {
		config.Logger.Errorf("Failed to write token to response body: %s", err)
	}
}
