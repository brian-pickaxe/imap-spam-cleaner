package inbox

import (
	"bytes"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dominicgisler/imap-spam-cleaner/app"
	"github.com/dominicgisler/imap-spam-cleaner/config"
	"github.com/dominicgisler/imap-spam-cleaner/imap"
	"github.com/dominicgisler/imap-spam-cleaner/logx"
	"github.com/dominicgisler/imap-spam-cleaner/provider"
	"github.com/go-co-op/gocron/v2"
)

func Schedule(ctx app.Context) {

	s, err := gocron.NewScheduler()
	if err != nil {
		logx.Errorf("Could not create scheduler: %v", err)
		return
	}

	for i, inbox := range ctx.Config.Inboxes {
		logx.Infof("Scheduling inbox %s (%s)", inbox.Username, inbox.Schedule)
		prov, ok := ctx.Config.Providers[inbox.Provider]
		if !ok {
			logx.Errorf("Invalid provider %s for inbox %d", inbox.Provider, i)
			continue
		}
		if _, err = s.NewJob(
			gocron.CronJob(inbox.Schedule, false),
			gocron.NewTask(processInbox, ctx, inbox, prov),
		); err != nil {
			logx.Errorf("Could not schedule inbox %s (%s): %v", inbox.Username, inbox.Schedule, err)
		}
	}

	s.Start()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	sig := <-ch
	logx.Debugf("Received %s, shutting down", sig.String())

	if err = s.Shutdown(); err != nil {
		logx.Errorf("Could not shutdown scheduler: %v ", err)
	}
}

func RunAllInboxes(ctx app.Context) {
	for i, inbox := range ctx.Config.Inboxes {
		logx.Infof("Processing inbox %s", inbox.Username)
		prov, ok := ctx.Config.Providers[inbox.Provider]
		if !ok {
			logx.Errorf("Invalid provider %s for inbox %d", inbox.Provider, i)
			continue
		}
		processInbox(ctx, inbox, prov)
	}
}

func processInbox(ctx app.Context, inbox config.Inbox, prov config.Provider) {

	var err error
	var p provider.Provider
	var im *imap.Imap
	var n int

	logx.Infof("Handling %s", inbox.Username)

	if im, err = imap.New(inbox); err != nil {
		logx.Errorf("Could not load imap: %v\n", err)
		return
	}
	defer im.Close()

	p, err = provider.New(prov.Type)
	if err != nil {
		logx.Errorf("Could not load provider: %v\n", err)
		return
	}

	if err = p.Init(prov.Config); err != nil {
		logx.Errorf("Could not init provider: %v\n", err)
		return
	}

	moved := 0
	batchSize := inbox.BatchSize
	if batchSize <= 0 {
		batchSize = imap.DefaultBatchSize
	}
	total, err := im.ProcessBatches(batchSize, func(msgs []imap.Message, offset, totalCount int) error {
		for i, m := range msgs {
			status := offset + i + 1
			if wl, ok := ctx.Config.Whitelists[inbox.Whitelist]; ok {
				trustedSender := false
				for _, rgx := range wl {
					if rgx.Match([]byte(m.From)) {
						trustedSender = true
						break
					}
				}
			if trustedSender {
				logx.Debugf("message %d/%d Skipping message #%d (%s) because of trusted sender (%s) date=%s size=%d", status, totalCount, m.UID, m.Subject, m.From, m.Date.Format(time.RFC3339), len(m.Raw))
				continue
			}
		}

			// If any header_spam_terms match in the headers, treat as spam and skip the provider.
			headerMatched := len(inbox.HeaderSpamTerms) > 0 && headersContainAny(m.Raw, inbox.HeaderSpamTerms)
			if headerMatched {
				n = 100
				logx.Debugf("message %d/%d Spam score of message #%d (%s): %s (header match, skipped scan) date=%s size=%d", status, totalCount, m.UID, m.Subject, logx.ColorScore(n), m.Date.Format(time.RFC3339), len(m.Raw))
			} else {
				if n, err = p.Analyze(m); err != nil {
					logx.Errorf("Could not analyze message (%s): %v\n", m.Subject, err)
					continue
				}
				logx.Debugf("message %d/%d Spam score of message #%d (%s): %s date=%s size=%d", status, totalCount, m.UID, m.Subject, logx.ColorScore(n), m.Date.Format(time.RFC3339), len(m.Raw))
			}

			if n >= inbox.MinScore {
				if ctx.Options.AnalyzeOnly {
					logx.Debugf("message %d/%d Analyze only mode, not moving message #%d date=%s size=%d", status, totalCount, m.UID, m.Date.Format(time.RFC3339), len(m.Raw))
					continue
				}

				// Subject term: header-matched spam uses header_spam_subject_term; high provider score uses high_spam_subject_term.
				var subjectTerm string
				if headerMatched && inbox.HeaderSpamSubjectTerm != "" {
					subjectTerm = inbox.HeaderSpamSubjectTerm
				} else if inbox.HighSpamSubjectTerm != "" && inbox.HighSpamScore > 0 && n >= inbox.HighSpamScore {
					subjectTerm = inbox.HighSpamSubjectTerm
				}
				if subjectTerm != "" {
					modifiedRaw := imap.PrependSubjectTerm(m.Raw, subjectTerm)
					if modifiedRaw != nil {
						if err = im.MoveMessageWithSubject(m.UID, inbox.Spam, modifiedRaw); err != nil {
							logx.Errorf("Could not move message with subject (%s): %v\n", m.Subject, err)
							continue
						}
					} else {
						if err = im.MoveMessage(m.UID, inbox.Spam); err != nil {
							logx.Errorf("Could not move message (%s): %v\n", m.Subject, err)
							continue
						}
					}
				} else {
					if err = im.MoveMessage(m.UID, inbox.Spam); err != nil {
						logx.Errorf("Could not move message (%s): %v\n", m.Subject, err)
						continue
					}
				}
				moved++
			}
		}
		return nil
	})
	if err != nil {
		logx.Errorf("Could not process messages: %v\n", err)
		return
	}

	logx.Infof("Loaded %d messages", total)
	logx.Infof("Moved %d messages", moved)
}

// headersContainAny returns true if any of the terms appear in the RFC822 header section (case-insensitive).
func headersContainAny(raw []byte, terms []string) bool {
	// Headers end at first blank line.
	sep := []byte("\r\n\r\n")
	if i := bytes.Index(raw, sep); i >= 0 {
		raw = raw[:i]
	} else if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		raw = raw[:i]
	}
	lower := strings.ToLower(string(raw))
	for _, t := range terms {
		if t == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(t)) {
			return true
		}
	}
	return false
}
