package modsec_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zwarder/waf/gobackend/internal/modsec"
	"github.com/zwarder/waf/gobackend/internal/storage"
)

func newSvc(t *testing.T) *modsec.Service {
	t.Helper()
	st := storage.NewLocalFS(t.TempDir(), "test")
	return modsec.New(st, storage.NewPublisher(st))
}

// --- GetConfig / GetRules missing file → ErrConfigNotFound ---

func TestGetConfig_Missing(t *testing.T) {
	svc := newSvc(t)
	_, _, err := svc.GetConfig()
	require.Error(t, err)
	assert.True(t, errors.Is(err, modsec.ErrConfigNotFound), "expected ErrConfigNotFound, got %v", err)
}

func TestGetRules_Missing(t *testing.T) {
	svc := newSvc(t)
	_, _, err := svc.GetRules()
	require.Error(t, err)
	assert.True(t, errors.Is(err, modsec.ErrConfigNotFound), "expected ErrConfigNotFound, got %v", err)
}

// --- UpdateConfig creates dir if absent, round-trip ---

func TestUpdateConfig_RoundTrip(t *testing.T) {
	// The store creates parent dirs on write (localFS Put does MkdirAll).
	svc := newSvc(t)

	content := "SecRuleEngine On\n"
	p, err := svc.UpdateConfig(content)
	require.NoError(t, err)
	assert.NotEmpty(t, p)

	got, gotPath, err := svc.GetConfig()
	require.NoError(t, err)
	assert.Equal(t, content, got)
	assert.Equal(t, p, gotPath)
}

// --- UpdateRules / GetRules round-trip ---

func TestUpdateRules_RoundTrip(t *testing.T) {
	svc := newSvc(t)

	content := "SecRule ARGS \"@rx test\" \"id:2001,phase:1,pass\"\n"
	p, err := svc.UpdateRules(content)
	require.NoError(t, err)

	got, gotPath, err := svc.GetRules()
	require.NoError(t, err)
	assert.Equal(t, content, got)
	assert.Equal(t, p, gotPath)
}

// --- AddRule happy path ---

func TestAddRule_HappyPath(t *testing.T) {
	svc := newSvc(t)

	// Seed rules.conf with existing content.
	initial := "SecRule ARGS \"@rx existing\" \"id:1000,phase:1,pass\"\n"
	_, err := svc.UpdateRules(initial)
	require.NoError(t, err)

	newRule := `SecRule ARGS "@rx test" "id:1001,phase:2,deny,msg:'test',severity:'5'"`
	id, p, err := svc.AddRule(newRule)
	require.NoError(t, err)
	assert.EqualValues(t, 1001, id)
	assert.NotEmpty(t, p)

	content, _, err := svc.GetRules()
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(content, newRule+"\n"), "rule should be appended: %q", content)
	assert.True(t, strings.Contains(content, initial[:len(initial)-1]), "original content must be present")
}

// --- AddRule with missing rules.conf → ErrConfigNotFound ---

func TestAddRule_MissingRulesFile(t *testing.T) {
	svc := newSvc(t)
	_, _, err := svc.AddRule(`SecRule ARGS "@rx x" "id:1,phase:1,pass"`)
	require.Error(t, err)
	assert.True(t, errors.Is(err, modsec.ErrConfigNotFound))
}

// --- AddRule with no id → ErrInvalidRule ---

func TestAddRule_NoID(t *testing.T) {
	svc := newSvc(t)
	_, err := svc.UpdateRules("")
	require.NoError(t, err)

	_, _, err = svc.AddRule(`SecRule ARGS "@rx test" "phase:2,deny"`)
	require.Error(t, err)
	assert.True(t, errors.Is(err, modsec.ErrInvalidRule))
}

// --- ListRules ---

func TestListRules_MultipleRules(t *testing.T) {
	svc := newSvc(t)

	rules := `# This is a comment
Include /etc/modsec/base.conf

SecRule ARGS "@rx sql" "id:1001,phase:2,deny,msg:'SQL injection',severity:'5'"
SecRule ARGS "@rx xss" "id:'1002',phase:1,pass,msg:'XSS attempt'"

`
	_, err := svc.UpdateRules(rules)
	require.NoError(t, err)

	items, err := svc.ListRules()
	require.NoError(t, err)
	require.Len(t, items, 2)

	// First rule
	r1 := items[0]
	assert.EqualValues(t, 1001, r1.ID)
	assert.Equal(t, "SQL injection", r1.Message)
	require.NotNil(t, r1.Phase)
	assert.EqualValues(t, 2, *r1.Phase)
	assert.Equal(t, "deny", r1.Action)
	require.NotNil(t, r1.Severity)
	assert.EqualValues(t, 5, *r1.Severity)

	// Second rule (id with quotes, no severity, pass)
	r2 := items[1]
	assert.EqualValues(t, 1002, r2.ID)
	assert.Equal(t, "XSS attempt", r2.Message)
	require.NotNil(t, r2.Phase)
	assert.EqualValues(t, 1, *r2.Phase)
	assert.Equal(t, "pass", r2.Action)
	assert.Nil(t, r2.Severity)
}

func TestListRules_SkipsCommentsAndBlank(t *testing.T) {
	svc := newSvc(t)

	content := `
# comment line
Include /etc/modsec/base.conf

SecRule ARGS "@rx test" "id:2001,phase:3,drop"
`
	_, err := svc.UpdateRules(content)
	require.NoError(t, err)

	items, err := svc.ListRules()
	require.NoError(t, err)
	require.Len(t, items, 1)
	assert.EqualValues(t, 2001, items[0].ID)
	assert.Equal(t, "drop", items[0].Action)
}

func TestListRules_DefaultsWhenFieldsMissing(t *testing.T) {
	svc := newSvc(t)

	// Rule with no msg, no phase, no action keyword, no severity.
	// action defaults to "pass", others nil/"".
	content := `SecRule ARGS "@rx bare" "id:3001"`
	_, err := svc.UpdateRules(content)
	require.NoError(t, err)

	items, err := svc.ListRules()
	require.NoError(t, err)
	require.Len(t, items, 1)
	r := items[0]
	assert.EqualValues(t, 3001, r.ID)
	assert.Equal(t, "", r.Message)
	assert.Nil(t, r.Phase)
	assert.Equal(t, "pass", r.Action)
	assert.Nil(t, r.Severity)
}

// --- DeleteRule ---

func TestDeleteRule_Deletes(t *testing.T) {
	svc := newSvc(t)

	content := "SecRule ARGS \"@rx sql\" \"id:1001,phase:2,deny\"\nSecRule ARGS \"@rx xss\" \"id:1002,phase:1,pass\"\n"
	_, err := svc.UpdateRules(content)
	require.NoError(t, err)

	deleted, err := svc.DeleteRule(1001)
	require.NoError(t, err)
	assert.True(t, deleted)

	got, _, err := svc.GetRules()
	require.NoError(t, err)
	assert.NotContains(t, got, "id:1001")
	assert.Contains(t, got, "id:1002")
}

func TestDeleteRule_NotFound(t *testing.T) {
	svc := newSvc(t)

	content := "SecRule ARGS \"@rx sql\" \"id:1001,phase:2,deny\"\n"
	_, err := svc.UpdateRules(content)
	require.NoError(t, err)

	deleted, err := svc.DeleteRule(9999)
	require.NoError(t, err)
	assert.False(t, deleted)

	// Content unchanged.
	got, _, err := svc.GetRules()
	require.NoError(t, err)
	assert.Equal(t, content, got)
}

// --- AddRule rstrip behavior: trailing whitespace stripped before append ---

func TestAddRule_RstripBeforeAppend(t *testing.T) {
	svc := newSvc(t)

	// Seed with trailing whitespace / newlines.
	initial := "SecRule ARGS \"@rx x\" \"id:1000,phase:1,pass\"\n\n\n"
	_, err := svc.UpdateRules(initial)
	require.NoError(t, err)

	newRule := `SecRule ARGS "@rx y" "id:1001,phase:1,pass"`
	_, _, err = svc.AddRule(newRule)
	require.NoError(t, err)

	got, _, err := svc.GetRules()
	require.NoError(t, err)

	// Must not have double-blank lines between old content and new rule.
	assert.True(t, strings.Contains(got, "id:1000,phase:1,pass\"\n"+newRule+"\n"),
		"rstrip must remove trailing newlines before appending; got:\n%s", got)
}
