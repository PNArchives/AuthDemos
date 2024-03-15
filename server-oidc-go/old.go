package main

// import (
// 	"encoding/json"
// 	"fmt"
// 	"io"
// 	"log/slog"
// 	"net/http"
// 	"net/url"
// 	"strings"
// )

// func helloHandler(w http.ResponseWriter, r *http.Request) {
// 	data := []byte(`Hello World!`)
// 	_, err := w.Write(data)
// 	if err != nil {
// 		slog.Error("Failed to write response", "error", err)
// 	}
// }

// func main() {
// 	http.HandleFunc("/hello", helloHandler)
// 	http.Handle("/", http.RedirectHandler("/start", http.StatusFound))
// 	http.HandleFunc("/start", start)
// 	http.HandleFunc("/oidc-callback", callback)

// 	slog.Info("Starting server in http://localhost:8080 ...")
// 	if err := http.ListenAndServe(":8080", nil); err != nil {
// 		slog.Error("Failed to start server", "error", err)
// 	}
// }

// const (
// 	responseType = "code"
// 	grantType    = "authorization_code"

// 	state               = "xyz"
// 	scope               = "openid"
// 	codeChallengeMethod = "S256"

// 	// https://tex2e.github.io/rfc-translater/html/rfc7636.html
// 	// 付録B. S256 code_challenge_methodの例 "
// 	// verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
// )

// // https://auth0.com/docs/authorization/flows/call-your-api-using-the-authorization-code-flow-with-pkce#javascript-sample
// // func base64URLEncode() string {
// // 	hash := sha256.Sum256([]byte(verifier))
// // 	return base64.RawURLEncoding.EncodeToString(hash[:])
// // }

// func start(w http.ResponseWriter, r *http.Request) {
// 	// PKCE用パラメータ
// 	// codeChallenge := base64URLEncode()
// 	// values.Add("code_challenge_method", codeChallengeMethod)
// 	// values.Add("code_challenge", codeChallenge)
// }

// func tokenRequest(query url.Values) (map[string]interface{}, error) {
// 	// PKCE用パラメータ
// 	// values.Add("code_verifier", verifier)
// }

// // 取得したトークンを利用してリソースにアクセス
// func apiRequest(req *http.Request, token string) ([]byte, error) {

// 	photoAPI := "https://photoslibrary.googleapis.com/v1/mediaItems"

// 	req, err := http.NewRequest("GET", photoAPI, nil)
// 	if err != nil {
// 		return nil, err
// 	}
// 	// 取得したアクセストークンをHeaderにセットしてリソースサーバにリクエストを送る
// 	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
// 	client := &http.Client{}
// 	resp, err := client.Do(req)
// 	if err != nil || resp.StatusCode != 200 {
// 		slog.Error("Failed to get resource", "status_code", resp.StatusCode, "error", err)
// 		return nil, err
// 	}
// 	defer resp.Body.Close()

// 	body, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		slog.Error("Failed to read response body", "error", err)
// 		return nil, err
// 	}

// 	return body, nil
// }
