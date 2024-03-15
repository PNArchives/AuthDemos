package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
)

type OidcConfig struct {
	Issuer                            string   `json:"issuer"`
	AuthEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	DeviceEndpoint                    string   `json:"device_authorization_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	JWKsUri                           string   `json:"jwks_uri"`
	ResTypeSupported                  []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
}

var oidcConfig = getOidcConfig()

func getOidcConfig() *OidcConfig {
	slog.Info("OIDC設定情報を取得しています...")
	discoveryUri := issuerUri + "/.well-known/openid-configuration"
	req, err := http.NewRequest("GET", discoveryUri, nil)
	if err != nil {
		slog.Error("OIDC設定情報を取得するリクエストの作成に失敗しました", "error", err)
		return nil
	}
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		slog.Error("OIDC設定情報の取得に失敗しました", "error", err)
		return nil
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		slog.Error("OIDC設定情報の取得に失敗しました", "error", err)
		return nil
	}

	var config OidcConfig
	if err = json.Unmarshal(body, &config); err != nil {
		slog.Error("OIDC設定情報の取得に失敗しました", "error", err)
		return nil
	}

	slog.Info("OIDC設定情報を取得しました!")
	slog.Info("Auth  Endpoint: " + config.AuthEndpoint)
	slog.Info("Token Endpoint: " + config.TokenEndpoint)
	slog.Info("---------- ---------- ---------- ---------- ----------")
	return &config
}
