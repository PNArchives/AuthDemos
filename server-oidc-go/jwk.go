package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"
)

type JwkConfig struct {
	Keys []Jwk `json:"keys"`
}

// https://docs.aws.amazon.com/ja_jp/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html
type Jwk struct {
	Kid string `json:"kid"` // Key ID
	Alg string `json:"alg"` // Algorithm
	Kty string `json:"kty"` // Key type
	E   string `json:"e"`   // RSA exponent
	N   string `json:"n"`   // RSA modulus
	Use string `json:"use"` // Use
}

var jwkConfig = getJwkConfig()

func getJwkConfig() *JwkConfig {
	slog.Info("JWK設定情報を取得しています...")
	req, err := http.NewRequest("GET", oidcConfig.JWKsUri, nil)
	if err != nil {
		slog.Error("JWK設定情報を取得するリクエストの作成に失敗しました", "error", err)
		return nil
	}
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		slog.Error("JWK設定情報の取得に失敗しました", "error", err)
		return nil
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		slog.Error("JWK設定情報の取得に失敗しました", "error", err)
		return nil
	}

	var config JwkConfig
	if err = json.Unmarshal(body, &config); err != nil {
		slog.Error("JWK設定情報の取得に失敗しました", "error", err)
		return nil
	}

	slog.Info("JWK設定情報を取得しました!")
	slog.Info("JWK length: " + strconv.Itoa(len(config.Keys)))
	slog.Info("---------- ---------- ---------- ---------- ----------")
	return &config
}

func decodeBase64(s string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

// Library: https://github.com/golang-jwt/jwt

type JwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type UserClaims struct {
	Iss           string `json:"iss"`
	Azp           string `json:"azp"`
	Aud           string `json:"aud"`
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	AtHash        string `json:"at_hash"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Locale        string `json:"locale"`
	Iat           int64  `json:"iat"`
	Exp           int64  `json:"exp"`
}

/*
https://jwt.io
https://zenn.dev/takoyaki3/articles/a5f59a8c01d51a
https://qiita.com/KWS_0901/items/c842644b0c65685b2526
https://zenn.dev/satoken/articles/oauth-funiki
https://zenn.dev/satoken/articles/oidc-client-golang
*/

func verifyIDToken(tokenString string) bool {
	splittedToken := strings.Split(tokenString, ".")

	headerBytes, err := decodeBase64(splittedToken[0])
	if err != nil {
		slog.Error("IDトークンのヘッダーの復号化に失敗しました", "error", err)
		return false
	}
	payloadBytes, err := decodeBase64(splittedToken[1])
	if err != nil {
		slog.Error("IDトークンのペーロードの復号化に失敗しました", "error", err)
		return false
	}
	// signature, err := decodeBase64(splittedToken[2])
	// if err != nil {
	// 	slog.Error("IDトークンの署名の復号化に失敗しました", "error", err)
	// 	return false
	// }

	var header JwtHeader
	var payload UserClaims

	if err := json.Unmarshal(headerBytes, &header); err != nil {
		slog.Error("IDトークンのヘッダーの復号化に失敗しました", "error", err)
		return false
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		slog.Error("IDトークンのペーロードの復号化に失敗しました", "error", err)
		return false
	}
	slog.Info("---------- ---------- ---------- ---------- ----------")

	for _, jwk := range jwkConfig.Keys {
		if jwk.Kid != header.Kid {
			continue
		}
		certString := jwk.N
		block, _ := pem.Decode([]byte(certString))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			slog.Error("x509.ParseCertificate() が失敗しました", "error", err)
			return false
		}
		rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return rsaPublicKey, nil
		})
		if err != nil {
			slog.Error("jwt.Parse() が失敗しました", "error", err)
			return false
		}
		fmt.Println(token)
		break
	}

	return true
}
