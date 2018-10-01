package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/spf13/viper"
	"gopkg.in/square/go-jose.v2/jwt"
)

type Config struct {
	Token   string    `json:"token"`
	Issuers []*Issuer `json:"issuers"`
}

type Issuer struct {
	Issuer          string      `json:"issuer"`
	PublicKey       string      `json:"publicKey"`
	ParsedPublicKey interface{} // *rsa.PublicKey, *dsa.PublicKey or *ecdsa.PublicKey
}

func main() {
	if err := mainE(); err != nil {
		panic(err)
	}
}

func mainE() error {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")

	err := viper.ReadInConfig()
	if err != nil {
		return fmt.Errorf("failed to read config: %s", err)
	}

	var config Config
	err = viper.Unmarshal(&config)
	if err != nil {
		return fmt.Errorf("failed to unmarshal config: %s", err)
	}

	for _, issuer := range config.Issuers {
		err := issuer.parsePublicKey()
		if err != nil {
			return err
		}
	}

	for _, issuer := range config.Issuers {
		claims, err := issuer.getClaims(config.Token)
		if err != nil {
			fmt.Printf("failed to get claims: %s\n", err)
		} else {
			fmt.Printf("Claims: %+v\n", claims)
			return nil
		}
	}

	return fmt.Errorf("failed to validate token")
}

func (issuer *Issuer) parsePublicKey() error {
	block, _ := pem.Decode([]byte(issuer.PublicKey))
	if block == nil {
		return fmt.Errorf("failed to read PEM block for issuer '%s'", issuer.Issuer)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key for issuer '%s': %s", issuer.Issuer, err)
	}

	issuer.ParsedPublicKey = pub
	return nil
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
		//Time:   time.Now(),
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
