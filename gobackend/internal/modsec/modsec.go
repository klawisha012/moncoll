// Package modsec manages ModSecurity config + rule files, reproducing
// backend/src/modsecurity/service.py.
package modsec

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var ErrConfigNotFound = errors.New("config not found")
var ErrInvalidRule = errors.New("rule must contain an id")

// Package-level compiled regexes for ListRules extraction.
// Note: idRe allows optional quotes (id:'?(\d+)'?) matching Python list_rules.
// addIdRe does NOT allow quotes, matching Python add_rule which uses id:(\d+).
var (
	idRe    = regexp.MustCompile(`id:'?(\d+)'?`)
	msgRe   = regexp.MustCompile(`msg:'([^']*)'`)
	phaseRe = regexp.MustCompile(`phase:(\d+)`)
	actionRe = regexp.MustCompile(`(deny|pass|drop|redirect|proxy)`)
	sevRe   = regexp.MustCompile(`severity:'?(\d+)'?`)
	addIdRe = regexp.MustCompile(`id:(\d+)`)
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

// Service manages a modsecurity config directory.
type Service struct{ dir string }

// New returns a Service rooted at dir (default /app/etc/angie/modsecurity).
func New(dir string) *Service { return &Service{dir: dir} }

func (s *Service) configFile() string { return filepath.Join(s.dir, "modsecurity.conf") }
func (s *Service) rulesFile() string  { return filepath.Join(s.dir, "rules.conf") }

// GetConfig reads modsecurity.conf; returns ErrConfigNotFound if missing.
func (s *Service) GetConfig() (content string, path string, err error) {
	p := s.configFile()
	b, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", p, fmt.Errorf("modsecurity.conf not found: %w", ErrConfigNotFound)
		}
		return "", p, err
	}
	return string(b), p, nil
}

// GetRules reads rules.conf; returns ErrConfigNotFound if missing.
func (s *Service) GetRules() (content string, path string, err error) {
	p := s.rulesFile()
	b, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", p, fmt.Errorf("rules.conf not found: %w", ErrConfigNotFound)
		}
		return "", p, err
	}
	return string(b), p, nil
}

// UpdateConfig writes content to modsecurity.conf, creating parent dirs as needed.
func (s *Service) UpdateConfig(content string) (path string, err error) {
	p := s.configFile()
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return p, err
	}
	return p, os.WriteFile(p, []byte(content), 0o644)
}

// UpdateRules writes content to rules.conf, creating parent dirs as needed.
func (s *Service) UpdateRules(content string) (path string, err error) {
	p := s.rulesFile()
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return p, err
	}
	return p, os.WriteFile(p, []byte(content), 0o644)
}

// AddRule appends rule to rules.conf and returns the parsed rule id.
// Mirrors Python add_rule: calls get_rules first (so ErrConfigNotFound if missing),
// then searches for id:(\d+) — no quotes — returning ErrInvalidRule if absent.
func (s *Service) AddRule(rule string) (id int64, path string, err error) {
	content, _, err := s.GetRules()
	if err != nil {
		return 0, s.rulesFile(), err
	}

	m := addIdRe.FindStringSubmatch(rule)
	if m == nil {
		return 0, s.rulesFile(), ErrInvalidRule
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
