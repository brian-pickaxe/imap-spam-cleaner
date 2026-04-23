package provider

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/dominicgisler/imap-spam-cleaner/imap"
	"github.com/ollama/ollama/api"
)

// defaultOllamaTimeout is the HTTP client timeout for each Ollama /api/chat call
// (connect + read body). Local large models can run for several minutes.
const defaultOllamaTimeout = 10 * time.Minute

type Ollama struct {
	AIBase
	client  *api.Client
	url     *url.URL
	timeout time.Duration
}

func (p *Ollama) Name() string {
	return "ollama"
}

func (p *Ollama) ValidateConfig(config map[string]string) error {

	if err := p.AIBase.ValidateConfig(config); err != nil {
		return err
	}

	if config["url"] == "" {
		return errors.New("ollama url is required")
	}

	u, err := url.Parse(config["url"])
	if err != nil {
		return err
	}
	p.url = u

	if p.timeout, err = parseOllamaHTTPTimeout(config); err != nil {
		return err
	}

	return nil
}

func (p *Ollama) Init(config map[string]string) error {
	if err := p.ValidateConfig(config); err != nil {
		return err
	}
	hc := &http.Client{Timeout: p.timeout}
	p.client = api.NewClient(p.url, hc)
	return nil
}

// parseOllamaHTTPTimeout reads optional "timeout" from ollama config: go duration (e.g. 10m, 90s) or seconds as a number.
func parseOllamaHTTPTimeout(config map[string]string) (time.Duration, error) {
	v := config["timeout"]
	if v == "" {
		return defaultOllamaTimeout, nil
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d, nil
	}
	t, err := strconv.ParseFloat(v, 64)
	if err != nil || t <= 0 {
		return 0, errors.New("ollama timeout must be a duration (e.g. 10m, 90s) or a positive number of seconds")
	}
	return time.Duration(t * float64(time.Second)), nil
}

func (p *Ollama) Analyze(msg imap.Message) (int, error) {

	prompt, err := p.buildPrompt(msg)
	if err != nil {
		return 0, err
	}

	b := false
	req := api.ChatRequest{
		Model: p.model,
		Messages: []api.Message{
			{
				Role:    "system",
				Content: prompt,
			},
		},
		Stream: &b,
	}

	var resp string
	if err = p.client.Chat(context.Background(), &req, func(response api.ChatResponse) error {
		resp = response.Message.Content
		return nil
	}); err != nil {
		return 0, err
	}

	i, err := strconv.ParseInt(resp, 10, 64)
	if err != nil {
		return 0, err
	}

	return int(i), nil
}
