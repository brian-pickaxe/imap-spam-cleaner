// Unsubscribe-junk is a standalone script that connects to each inbox's Junk/Spam
// folder (using config.yml) and HTTP GETs every List-Unsubscribe URL found in messages.
// Run from repo root: go run ./cmd/unsubscribe-junk
// Add cmd/unsubscribe-junk to .gitignore if you don't want to commit it.

package main

import (
	"bytes"
	"net/http"
	"regexp"
	"time"

	"github.com/dominicgisler/imap-spam-cleaner/config"
	"github.com/dominicgisler/imap-spam-cleaner/imap"
	"github.com/dominicgisler/imap-spam-cleaner/logx"
	"github.com/emersion/go-message/mail"
)

// listUnsubscribeURL matches HTTP/HTTPS URLs in List-Unsubscribe header (e.g. <https://...>).
var listUnsubscribeURL = regexp.MustCompile(`https?://[^\s>]+`)

func main() {
	c, err := config.Load()
	if err != nil {
		logx.Errorf("Could not load config: %v", err)
		return
	}

	for i, inbox := range c.Inboxes {
		logx.Infof("Processing Junk folder for %s (inbox %d/%d)", inbox.Username, i+1, len(c.Inboxes))
		if err := processJunkFolder(inbox); err != nil {
			logx.Errorf("Junk folder for %s: %v", inbox.Username, err)
		}
	}
}

func processJunkFolder(inbox config.Inbox) error {
	im, err := imap.New(inbox)
	if err != nil {
		return err
	}
	defer im.Close()

	batchSize := inbox.BatchSize
	if batchSize <= 0 {
		batchSize = imap.DefaultBatchSize
	}

	client := &http.Client{Timeout: 15 * time.Second}
	hit := 0

	_, err = im.ProcessBatchesInMailbox(inbox.Spam, batchSize, func(msgs []imap.Message, offset, total int) error {
		for _, m := range msgs {
			urls := extractUnsubscribeURLs(m.Raw)
			for _, u := range urls {
				hit++
				logx.Infof("message #%d: GET %s", m.UID, u)
				resp, err := client.Get(u)
				if err != nil {
					logx.Warnf("GET %s: %v", u, err)
					continue
				}
				_ = resp.Body.Close()
				logx.Infof("  -> %s", resp.Status)
			}
		}
		return nil
	})

	if err != nil {
		return err
	}
	logx.Infof("Hit %d unsubscribe URLs in %s", hit, inbox.Spam)
	return nil
}

// extractUnsubscribeURLs parses the raw RFC822 message and returns HTTP/HTTPS URLs
// from the List-Unsubscribe header (and List-Unsubscribe-Post if present).
func extractUnsubscribeURLs(raw []byte) []string {
	mr, err := mail.CreateReader(bytes.NewReader(raw))
	if err != nil {
		return nil
	}
	header := mr.Header

	var out []string
	for _, name := range []string{"List-Unsubscribe", "List-Unsubscribe-Post"} {
		val := header.Get(name)
		for _, u := range listUnsubscribeURL.FindAllString(val, -1) {
			out = append(out, u)
		}
	}
	return out
}
