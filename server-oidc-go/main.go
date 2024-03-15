package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	issuerUri   = "https://accounts.google.com"
	redirectUri = "http://localhost:8080/oidc-callback"

	clientId     = "36690019565-4v24afjljaba9k0v249iofg06e55fehb.apps.googleusercontent.com"
	clientSecret = "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"
)

func main() {
	fmt.Println(oidcConfig.JWKsUri)
	fmt.Println(len(jwkConfig.Keys))

	idToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjU1YzE4OGE4MzU0NmZjMTg4ZTUxNTc2YmE3MjgzNmUwNjAwZThiNzMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIzNjY5MDAxOTU2NS00djI0YWZqbGphYmE5azB2MjQ5aW9mZzA2ZTU1ZmVoYi5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImF1ZCI6IjM2NjkwMDE5NTY1LTR2MjRhZmpsamFiYTlrMHYyNDlpb2ZnMDZlNTVmZWhiLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwic3ViIjoiMTA1NzQ1MDM1MDAyODA3NTIwODk5IiwiZW1haWwiOiJ4aWFvaGFvY3N6QGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoidGZjeml3Rm1seWFhUXlPZzNSQmtaQSIsIm5hbWUiOiJyeW9zdWtlIGlnYXJhc2hpIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FDZzhvY0lxTzBjN05ZVUFrZ1FxT3VxTld3TEJsamJOcEhHMjZoUVVtZk9VZkl0ZD1zOTYtYyIsImdpdmVuX25hbWUiOiJyeW9zdWtlIiwiZmFtaWx5X25hbWUiOiJpZ2FyYXNoaSIsImxvY2FsZSI6InpoLUNOIiwiaWF0IjoxNzA4NzgxNTA1LCJleHAiOjE3MDg3ODUxMDV9.eVNOUFB0cMcn1ZCC3DjWMa6ultvoVcGNcNt3JMk1nKPM6jNpBBIretE_eZVowy0SJ5Zb0TRASQCb2qPjyqk1jjzxUkxLPnhVXzcg_DsBcvCPardYe55vhyA-uQf1BjZs640j6IOKlV5WMh3KiZBpiR7JHtxlI8DSoQzIE3dosO7itS7dRhU_ZldIaLxmmg2Whxc96BMwwhlJi5cFJZC4P-fbLeB2eZ9fRCRTa4_-Vz0d6jPFimqNXf57wM4vDVeRGxrA744-_xS_nemkEblZXz4snFE4v5rzkxfC4ATkx-ceFiS3zVqc8hpbVavPfBE8mzx7onoTWDUiIc_j3NBTtQ"
	verifyIDToken(idToken)
}

func Test() {
	addHandles()
	slog.Info("HTTPサーバーを起動しています: http://localhost:8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		slog.Error("HTTPサーバーの起動に失敗しました", "error", err)
	}
}

func addHandles() {
	http.Handle("/", http.RedirectHandler("/top", http.StatusFound))
	http.HandleFunc("/top", showTopPage)
	http.HandleFunc("/login-code", loginWithCodeFlow)
	http.HandleFunc("/oidc-callback", oidcCallback)
	http.HandleFunc("/post-login", postLogin)
}

func showTopPage(w http.ResponseWriter, r *http.Request) {
	html, err := template.ParseFiles("top.html")
	if err != nil {
		slog.Error("top.htmlのパースに失敗しました", "error", err)
		return
	}
	if err := html.Execute(w, nil); err != nil {
		slog.Error("top.htmlへのデータ埋め込みに失敗しました", "error", err)
	}
}

func loginWithCodeFlow(w http.ResponseWriter, r *http.Request) {
	slog.Info("Handler called: loginWithCodeFlow")
	resType := "code"
	scope := "openid email profile"
	state := "xyz" // 任意の文字列でOK

	values := url.Values{}
	values.Add("response_type", resType)
	values.Add("client_id", clientId)
	values.Add("scope", scope)
	values.Add("state", state)
	values.Add("redirect_uri", redirectUri)

	loginUri := oidcConfig.AuthEndpoint + "?" + values.Encode()
	slog.Info("(Code Flow) Redirect to: " + loginUri)
	http.Redirect(w, r, loginUri, http.StatusFound)
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
}

func oidcCallback(w http.ResponseWriter, r *http.Request) {
	slog.Info("Handler called: oidcCallback")
	query := r.URL.Query()
	code := query.Get("code")
	if code == "" {
		slog.Error("codeの取得に失敗しました")
		return
	}
	state := query.Get("state")
	if state == "" {
		slog.Error("stateの取得に失敗しました")
		return
	}
	fmt.Println("code: " + code)
	fmt.Println("state: " + state)

	grantType := "authorization_code"
	values := url.Values{}
	values.Add("client_id", clientId)
	values.Add("client_secret", clientSecret)
	values.Add("grant_type", grantType)
	values.Add("code", code)
	values.Add("redirect_uri", redirectUri)
	req, err := http.NewRequest("POST", oidcConfig.TokenEndpoint, strings.NewReader(values.Encode()))
	if err != nil {
		slog.Error("トークンリクエストの作成に失敗しました", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		slog.Error("トークンリクエストの送信に失敗しました", "error", err)
		return
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		slog.Error("トークンリクエストの受信に失敗しました", "error", err)
		return
	}
	slog.Info("トークンレスポンス: " + res.Status)

	var tokenResponse TokenResponse
	if err = json.Unmarshal(body, &tokenResponse); err != nil {
		slog.Error("トークンレスポンスのパースに失敗しました", "error", err)
		return
	}
	fmt.Println("access_token: " + tokenResponse.AccessToken)
	fmt.Println("id_token: " + tokenResponse.IDToken)
	fmt.Println("scope: " + tokenResponse.Scope)
	fmt.Println("expires_in: " + strconv.Itoa(tokenResponse.ExpiresIn) + "秒")
	fmt.Println("token_type: " + tokenResponse.TokenType)
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	slog.Info("Handler called: postLogin")
}
