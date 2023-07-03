package turnstile

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"
)

const endpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

type turnstileResponse struct {
	Success   bool      `json:"success"`
	Codes     []string  `json:"error-codes"`
	Timestamp time.Time `json:"challenge_ts"`
	Hostname  string    `json:"hostname"`
}

type Turnstile struct {
	secret string
}

func NewTurnstile(secret string) *Turnstile {
	t := Turnstile{
		secret,
	}
	return &t
}

func (t *Turnstile) Verify(token string, ip string) (bool, error) {

	data, err := http.PostForm(endpoint, url.Values{
		"secret":   {t.secret},
		"response": {token},
		"remoteip": {ip},
	})

	if err != nil {
		return false, err
	}

	var body []byte
	defer data.Body.Close()
	body, err = io.ReadAll(data.Body)

	if err != nil {
		return false, err
	}

	response := turnstileResponse{}
	err = json.Unmarshal(body, &response)

	if err != nil {
		return false, err
	}

	return response.Success, nil

}
