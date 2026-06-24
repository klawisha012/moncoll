// Package modsec manages ModSecurity config + rule files, reproducing
// backend/src/modsecurity/service.py. State is written to the shared store so
// every edge node converges to the same WAF rules (horizontal scaling); each
// write is published as a manifest generation.
package modsec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/zwarder/waf/gobackend/internal/storage"
)

var ErrConfigNotFound = errors.New("config not found")
var ErrInvalidRule = errors.New("rule must contain an id")

// Canonical object keys for the global ModSecurity config (object-layout.md).
const (
	keyConfig = "modsec/modsecurity.conf"
	keyRules  = "modsec/rules.conf"
)

// Package-level compiled regexes for ListRules extraction.
// Note: idRe allows optional quotes (id:'?(\d+)'?) matching Python list_rules.
// addIdRe does NOT allow quotes, matching Python add_rule which uses id:(\d+).
var (
	idRe     = regexp.MustCompile(`id:'?(\d+)'?`)
	msgRe    = regexp.MustCompile(`msg:'([^']*)'`)
	phaseRe  = regexp.MustCompile(`phase:(\d+)`)
	actionRe = regexp.MustCompile(`(deny|pass|drop|redirect|proxy)`)
	sevRe    = regexp.MustCompile(`severity:'?(\d+)'?`)
	addIdRe  = regexp.MustCompile(`id:(\d+)`)
)

// RuleItem mirrors the dict returned by ConfigService.list_rules() in Python.
type RuleItem struct {
	ID       int64
	Rule     string
	Message  string
	Phase    *int64
	Action   string
	Severity *int64
}

// Service manages the global ModSecurity config via the shared store.
type Service struct {
	store storage.Store
	pub   *storage.Publisher
}

// New returns a Service backed by the shared store. Writes go to the canonical
// modsec/ keys (mapped to /app/etc/angie/modsecurity in local mode).
func New(store storage.Store, pub *storage.Publisher) *Service {
	return &Service{store: store, pub: pub}
}

// read returns the object content, mapping a missing object to os.ErrNotExist
// so the GetConfig/GetRules ErrConfigNotFound contract is preserved.
func (s *Service) read(key string) (string, error) {
	rc, _, err := s.store.Get(context.Background(), key)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return "", os.ErrNotExist
		}
		return "", err
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	return string(b), err
}

// write stores content and publishes a new manifest generation.
func (s *Service) write(key, content string) error {
	oi, err := s.store.Put(context.Background(), key, strings.NewReader(content), storage.PutOptions{})
	if err != nil {
		return err
	}
	return s.pub.Publish(context.Background(), storage.ChangeSet{Changed: []storage.ObjectInfo{oi}})
}

// GetConfig reads modsecurity.conf; returns ErrConfigNotFound if missing.
func (s *Service) GetConfig() (content string, path string, err error) {
	c, err := s.read(keyConfig)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", keyConfig, fmt.Errorf("modsecurity.conf not found: %w", ErrConfigNotFound)
		}
		return "", keyConfig, err
	}
	return c, keyConfig, nil
}

// GetRules reads rules.conf; returns ErrConfigNotFound if missing.
func (s *Service) GetRules() (content string, path string, err error) {
	c, err := s.read(keyRules)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", keyRules, fmt.Errorf("rules.conf not found: %w", ErrConfigNotFound)
		}
		return "", keyRules, err
	}
	return c, keyRules, nil
}

// UpdateConfig writes content to modsecurity.conf and publishes it.
func (s *Service) UpdateConfig(content string) (path string, err error) {
	return keyConfig, s.write(keyConfig, content)
}

// UpdateRules writes content to rules.conf and publishes it.
func (s *Service) UpdateRules(content string) (path string, err error) {
	return keyRules, s.write(keyRules, content)
}

// AddRule appends rule to rules.conf and returns the parsed rule id.
// Mirrors Python add_rule: calls get_rules first (so ErrConfigNotFound if missing),
// then searches for id:(\d+) — no quotes — returning ErrInvalidRule if absent.
func (s *Service) AddRule(rule string) (id int64, path string, err error) {
	content, _, err := s.GetRules()
	if err != nil {
		return 0, keyRules, err
	}

	m := addIdRe.FindStringSubmatch(rule)
	if m == nil {
		return 0, keyRules, ErrInvalidRule
	}
	rid, _ := strconv.ParseInt(m[1], 10, 64)

	newContent := strings.TrimRight(content, " \t\r\n") + "\n" + rule + "\n"
	p, err := s.UpdateRules(newContent)
	return rid, p, err
}

// DeleteRule removes every line matching ^.*id:<id>[,\s].*$ (MULTILINE).
// Returns false if no match (content unchanged), true if deleted.
func (s *Service) DeleteRule(id int64) (deleted bool, err error) {
	content, _, err := s.GetRules()
	if err != nil {
		return false, err
	}

	re := regexp.MustCompile(`(?m)^.*id:` + strconv.FormatInt(id, 10) + `[,\s].*$`)
	newContent := re.ReplaceAllString(content, "")

	if newContent == content {
		return false, nil
	}
	_, err = s.UpdateRules(newContent)
	return true, err
}

// ListRules parses rules.conf and returns structured RuleItem values.
// Skips blank lines, comment lines (# …), and Include lines.
// Skips lines without an id field.
func (s *Service) ListRules() ([]RuleItem, error) {
	content, _, err := s.GetRules()
	if err != nil {
		return nil, err
	}

	var rules []RuleItem
	for _, line := range strings.Split(content, "\n") {
		stripped := strings.TrimSpace(line)
		if stripped == "" || strings.HasPrefix(stripped, "#") || strings.HasPrefix(stripped, "Include") {
			continue
		}

		idm := idRe.FindStringSubmatch(stripped)
		if idm == nil {
			continue
		}
		rid, _ := strconv.ParseInt(idm[1], 10, 64)

		msg := ""
		if mm := msgRe.FindStringSubmatch(stripped); mm != nil {
			msg = mm[1]
		}

		var phase *int64
		if pm := phaseRe.FindStringSubmatch(stripped); pm != nil {
			v, _ := strconv.ParseInt(pm[1], 10, 64)
			phase = &v
		}

		action := "pass"
		if am := actionRe.FindStringSubmatch(stripped); am != nil {
			action = am[1]
		}

		var severity *int64
		if sm := sevRe.FindStringSubmatch(stripped); sm != nil {
			v, _ := strconv.ParseInt(sm[1], 10, 64)
			severity = &v
		}

		rules = append(rules, RuleItem{
			ID:       rid,
			Rule:     stripped,
			Message:  msg,
			Phase:    phase,
			Action:   action,
			Severity: severity,
		})
	}
	return rules, nil
}
