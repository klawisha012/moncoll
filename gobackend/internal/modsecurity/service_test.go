package modsecurity

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	modsecurityv1 "github.com/zwarder/waf/gobackend/gen/modsecurity/v1"
	"github.com/zwarder/waf/gobackend/internal/modsec"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

type fakeReloader struct {
	ok  bool
	msg string
}

func (f fakeReloader) ReloadVerbose(_ context.Context) (bool, string) {
	return f.ok, f.msg
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newSvc(t *testing.T, reloader Reloader) *Service {
	t.Helper()
	cfg := modsec.New(t.TempDir())
	if reloader == nil {
		reloader = fakeReloader{ok: true, msg: "ok"}
	}
	return NewService(cfg, reloader)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestGetConfig_NotFound(t *testing.T) {
	svc := newSvc(t, nil)
	_, err := svc.GetConfig(context.Background(), &modsecurityv1.Empty2{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestGetRules_NotFound(t *testing.T) {
	svc := newSvc(t, nil)
	_, err := svc.GetRules(context.Background(), &modsecurityv1.Empty2{})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestListRules_AfterUpdateRules(t *testing.T) {
	svc := newSvc(t, nil)
	ctx := context.Background()

	// Seed rules.conf with two rules: one with phase+severity, one without phase.
	rulesContent := "SecRule REQUEST_URI \"@rx /admin\" \"id:1001,phase:2,deny,msg:'x',severity:'5'\"\n" +
		"SecRule ARGS \"@rx badword\" \"id:1002,deny,msg:'y'\"\n"
	_, err := svc.UpdateRules(ctx, &modsecurityv1.ConfigUpdate{Content: rulesContent})
	require.NoError(t, err)

	resp, err := svc.ListRules(ctx, &modsecurityv1.Empty2{})
	require.NoError(t, err)
	require.Len(t, resp.Rules, 2)

	// First rule: id=1001, phase=2, severity=5 (wrappers non-nil)
	r1 := resp.Rules[0]
	assert.Equal(t, int64(1001), r1.Id)
	require.NotNil(t, r1.Phase, "Phase wrapper should be non-nil for rule 1001")
	assert.Equal(t, int64(2), r1.Phase.Value)
	require.NotNil(t, r1.Severity, "Severity wrapper should be non-nil for rule 1001")
	assert.Equal(t, int64(5), r1.Severity.Value)

	// Second rule: id=1002, no phase
	r2 := resp.Rules[1]
	assert.Equal(t, int64(1002), r2.Id)
	assert.Nil(t, r2.Phase, "Phase should be nil for rule with no phase field")
}

func TestAddRule_Valid(t *testing.T) {
	svc := newSvc(t, nil)
	ctx := context.Background()

	// Seed rules.conf first (AddRule calls GetRules internally)
	_, err := svc.UpdateRules(ctx, &modsecurityv1.ConfigUpdate{Content: ""})
	require.NoError(t, err)

	rule := "SecRule REQUEST_URI \"@rx /foo\" \"id:2002,phase:1,deny,msg:'test'\""
	resp, err := svc.AddRule(ctx, &modsecurityv1.RuleCreate{Rule: rule})
	require.NoError(t, err)
	assert.True(t, resp.Success)
	require.NotNil(t, resp.Id)
	assert.Equal(t, int64(2002), resp.Id.Value)
}

func TestAddRule_NoId(t *testing.T) {
	svc := newSvc(t, nil)
	ctx := context.Background()

	// Seed rules.conf first
	_, err := svc.UpdateRules(ctx, &modsecurityv1.ConfigUpdate{Content: ""})
	require.NoError(t, err)

	rule := "SecRule REQUEST_URI \"@rx /foo\" \"deny\""
	_, err = svc.AddRule(ctx, &modsecurityv1.RuleCreate{Rule: rule})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDeleteRule_Found(t *testing.T) {
	svc := newSvc(t, nil)
	ctx := context.Background()

	// Seed and add rule 2002
	_, err := svc.UpdateRules(ctx, &modsecurityv1.ConfigUpdate{Content: ""})
	require.NoError(t, err)
	rule := "SecRule REQUEST_URI \"@rx /foo\" \"id:2002,phase:1,deny,msg:'test'\""
	_, err = svc.AddRule(ctx, &modsecurityv1.RuleCreate{Rule: rule})
	require.NoError(t, err)

	// Delete it
	result, err := svc.DeleteRule(ctx, &modsecurityv1.DeleteRuleRequest{RuleId: 2002})
	require.NoError(t, err)
	assert.IsType(t, &emptypb.Empty{}, result)
}

func TestDeleteRule_NotFound(t *testing.T) {
	svc := newSvc(t, nil)
	ctx := context.Background()

	// Seed rules.conf (no rules)
	_, err := svc.UpdateRules(ctx, &modsecurityv1.ConfigUpdate{Content: ""})
	require.NoError(t, err)

	_, err = svc.DeleteRule(ctx, &modsecurityv1.DeleteRuleRequest{RuleId: 9999})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestReload_AlwaysSucceeds_StatusLevel(t *testing.T) {
	// Even when the reloader reports failure, Reload must return nil gRPC error.
	svc := NewService(modsec.New(t.TempDir()), fakeReloader{ok: false, msg: "boom"})
	resp, err := svc.Reload(context.Background(), &modsecurityv1.Empty2{})
	require.NoError(t, err, "Reload must never return a gRPC error")
	assert.False(t, resp.Success)
	assert.Equal(t, "boom", resp.Message)
}
