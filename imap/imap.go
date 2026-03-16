package imap

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/dominicgisler/imap-spam-cleaner/config"
	"github.com/dominicgisler/imap-spam-cleaner/logx"
	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	_ "github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/mail"
)

type Imap struct {
	client *imapclient.Client
	cfg    config.Inbox
}

func New(cfg config.Inbox) (*Imap, error) {

	var err error
	var mailboxes []*imap.ListData

	i := &Imap{
		cfg: cfg,
	}

	if cfg.TLS {
		i.client, err = imapclient.DialTLS(fmt.Sprintf("%s:%d", cfg.Host, cfg.Port), nil)
	} else {
		i.client, err = imapclient.DialInsecure(fmt.Sprintf("%s:%d", cfg.Host, cfg.Port), nil)
	}

	if err != nil {
		i.Close()
		return nil, fmt.Errorf("failed to dial IMAP server: %w", err)
	}

	if err = i.client.Login(cfg.Username, cfg.Password).Wait(); err != nil {
		i.Close()
		return nil, fmt.Errorf("failed to login: %w", err)
	}

	mailboxes, err = i.client.List("", "*", nil).Collect()
	if err != nil {
		return nil, fmt.Errorf("failed to list mailboxes: %w", err)
	}

	logx.Debug("Available mailboxes:")
	for _, l := range mailboxes {
		logx.Debugf("  - %s", l.Mailbox)
	}

	return i, nil
}

// DefaultBatchSize is the number of messages to fetch and process at once.
// Processing in batches avoids loading 700+ hours of mail into memory at once.
const DefaultBatchSize = 500

func (i *Imap) Close() {
	if i.client != nil {
		i.client.Logout()
		_ = i.client.Close()
	}
}

// ProcessBatches fetches messages in batches of batchSize, calls process for each batch,
// then discards the batch so memory stays bounded. total is the number of UIDs in range.
func (i *Imap) ProcessBatches(batchSize int, process func(msgs []Message, offset, total int) error) (total int, err error) {
	if batchSize <= 0 {
		batchSize = DefaultBatchSize
	}

	mbox, err := i.client.Select(i.cfg.Inbox, nil).Wait()
	if err != nil {
		return 0, fmt.Errorf("failed to select INBOX: %w", err)
	}
	logx.Debugf("Found %d messages in inbox", mbox.NumMessages)

	searchCrit := &imap.SearchCriteria{}
	if i.cfg.MinAge > 0 {
		searchCrit.Before = time.Now().Add(-i.cfg.MinAge)
	}
	if i.cfg.MaxAge > 0 {
		searchCrit.Since = time.Now().Add(-i.cfg.MaxAge)
	}

	uidRes, err := i.client.UIDSearch(searchCrit, nil).Wait()
	if err != nil {
		return 0, fmt.Errorf("could not search UIDs: %w", err)
	}

	uids := uidRes.AllUIDs()
	total = len(uids)
	logx.Debugf("Found %d UIDs in timerange", total)
	if total == 0 {
		return 0, nil
	}

	fetchOptions := &imap.FetchOptions{
		Envelope: true,
		UID:      true,
		BodySection: []*imap.FetchItemBodySection{
			{Peek: true},
		},
	}

	for start := 0; start < total; start += batchSize {
		end := start + batchSize
		if end > total {
			end = total
		}
		batchSet := imap.UIDSet{}
		for _, uid := range uids[start:end] {
			batchSet.AddNum(uid)
		}

		msgs, err := i.client.Fetch(batchSet, fetchOptions).Collect()
		if err != nil {
			return total, fmt.Errorf("failed to fetch message batch (offset %d): %w", start, err)
		}

		messages := make([]Message, 0, len(msgs))
		for _, msg := range msgs {
			m, ok := i.parseFetchMessage(msg)
			if !ok {
				continue
			}
			if i.cfg.MinAge > 0 && m.Date.After(time.Now().Add(-i.cfg.MinAge)) || i.cfg.MaxAge > 0 && m.Date.Before(time.Now().Add(-i.cfg.MaxAge)) {
				logx.Debugf("skipping message because date is not in range (msg.UID=%d)", m.UID)
				continue
			}
			messages = append(messages, m)
		}

		if len(messages) > 0 {
			if err := process(messages, start, total); err != nil {
				return total, err
			}
		}
	}

	return total, nil
}

// ProcessBatchesInMailbox selects the given mailbox and processes all messages in batches.
// No date filtering is applied. Use this for Spam/Junk folders.
func (i *Imap) ProcessBatchesInMailbox(mailbox string, batchSize int, process func(msgs []Message, offset, total int) error) (total int, err error) {
	if batchSize <= 0 {
		batchSize = DefaultBatchSize
	}

	mbox, err := i.client.Select(mailbox, nil).Wait()
	if err != nil {
		return 0, fmt.Errorf("failed to select mailbox %q: %w", mailbox, err)
	}
	logx.Debugf("Found %d messages in %s", mbox.NumMessages, mailbox)

	uidRes, err := i.client.UIDSearch(&imap.SearchCriteria{}, nil).Wait()
	if err != nil {
		return 0, fmt.Errorf("could not search UIDs: %w", err)
	}

	uids := uidRes.AllUIDs()
	total = len(uids)
	if total == 0 {
		return 0, nil
	}

	fetchOptions := &imap.FetchOptions{
		Envelope: true,
		UID:      true,
		BodySection: []*imap.FetchItemBodySection{
			{Peek: true},
		},
	}

	for start := 0; start < total; start += batchSize {
		end := start + batchSize
		if end > total {
			end = total
		}
		batchSet := imap.UIDSet{}
		for _, uid := range uids[start:end] {
			batchSet.AddNum(uid)
		}

		msgs, err := i.client.Fetch(batchSet, fetchOptions).Collect()
		if err != nil {
			return total, fmt.Errorf("failed to fetch message batch (offset %d): %w", start, err)
		}

		messages := make([]Message, 0, len(msgs))
		for _, msg := range msgs {
			m, ok := i.parseFetchMessage(msg)
			if !ok {
				continue
			}
			messages = append(messages, m)
		}

		if len(messages) > 0 {
			if err := process(messages, start, total); err != nil {
				return total, err
			}
		}
	}

	return total, nil
}

// parseFetchMessage turns one FetchMessageBuffer into a Message. Returns (msg, true) on success.
func (i *Imap) parseFetchMessage(msg *imapclient.FetchMessageBuffer) (Message, bool) {
	var b []byte
	for _, buf := range msg.BodySection {
		b = buf.Bytes
		break
	}

	mr, err := mail.CreateReader(bytes.NewReader(b))
	if err != nil {
		logx.Warnf("failed to create message reader (msg.UID=%d): %v\n", msg.UID, err)
		return Message{}, false
	}

	m := Message{
		UID:         msg.UID,
		DeliveredTo: mr.Header.Get("Delivered-To"),
		From:        mr.Header.Get("From"),
		To:          mr.Header.Get("To"),
		Cc:          mr.Header.Get("Cc"),
		Bcc:         mr.Header.Get("Bcc"),
		Subject:     msg.Envelope.Subject,
		Contents:    []string{},
		Raw:         b,
	}

	if m.Date, err = mr.Header.Date(); err != nil {
		logx.Warnf("failed to load message date (msg.UID=%d): %v\n", msg.UID, err)
		return Message{}, false
	}

	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			logx.Warnf("failed to read message part (msg.UID=%d): %v\n", msg.UID, err)
			break
		}
		switch p.Header.(type) {
		case *mail.InlineHeader:
			if b, err = io.ReadAll(p.Body); err != nil {
				logx.Warnf("failed to read message body (msg.UID=%d): %v\n", msg.UID, err)
				break
			}
			m.Contents = append(m.Contents, string(b))
		}
	}

	return m, true
}

func (i *Imap) LoadMessages() ([]Message, error) {
	var messages []Message
	_, err := i.ProcessBatches(DefaultBatchSize, func(msgs []Message, _, _ int) error {
		messages = append(messages, msgs...)
		return nil
	})
	return messages, err
}

func (i *Imap) MoveMessage(uid imap.UID, mailbox string) error {
	uidSet := imap.UIDSet{}
	uidSet.AddNum(uid)
	if _, err := i.client.Move(uidSet, mailbox).Wait(); err != nil {
		return err
	}
	return nil
}
