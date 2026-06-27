// Package modsecurity implements the ModSecurityService gRPC server,
// reproducing backend/src/modsecurity/router.py semantics.
package modsecurity

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	modsecurityv1 "github.com/zwarder/waf/gobackend/gen/modsecurity/v1"
	"github.com/zwarder/waf/gobackend/internal/auth"
	"github.com/zwarder/waf/gobackend/internal/modsec"
)

// Reloader is satisfied by angie.ReloadVerbose (wrapped) or any test fake.
type Reloader interface {
	ReloadVerbose(ctx context.Context) (bool, string)
}

// Service implements modsecurityv1.ModSecurityServiceServer.
type Service struct {
	modsecurityv1.UnimplementedModSecurityServiceServer
	cfg      *modsec.Service
	reloader Reloader
}

func (s *Service) AuthLevels() map[string]auth.Level {
	return map[string]auth.Level{
		modsecurityv1.ModSecurityService_GetConfig_FullMethodName:    auth.LevelVerified,
		modsecurityv1.ModSecurityService_GetRules_FullMethodName:     auth.LevelVerified,
		modsecurityv1.ModSecurityService_ListRules_FullMethodName:    auth.LevelVerified,
		modsecurityv1.ModSecurityService_UpdateConfig_FullMethodName: auth.LevelAdmin,
		modsecurityv1.ModSecurityService_UpdateRules_FullMethodName:  auth.LevelAdmin,
		modsecurityv1.ModSecurityService_AddRule_FullMethodName:      auth.LevelAdmin,
		modsecurityv1.ModSecurityService_DeleteRule_FullMethodName:   auth.LevelAdmin,
		modsecurityv1.ModSecurityService_Reload_FullMethodName:       auth.LevelAdmin,
	}
}

// NewService constructs a ready-to-register Service.
func NewService(cfg *modsec.Service, r Reloader) *Service {
	return &Service{cfg: cfg, reloader: r}
}

// GetConfig returns modsecurity.conf contents; 404 if the file is absent.
func (s *Service) GetConfig(ctx context.Context, _ *modsecurityv1.Empty2) (*modsecurityv1.ConfigResponse, error) {
	content, path, err := s.cfg.GetConfig()
	if err != nil {
		if errors.Is(err, modsec.ErrConfigNotFound) {
			return nil, status.Error(codes.NotFound, "modsecurity.conf not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &modsecurityv1.ConfigResponse{Content: content, FilePath: path}, nil
}

// GetRules returns rules.conf contents; 404 if the file is absent.
func (s *Service) GetRules(ctx context.Context, _ *modsecurityv1.Empty2) (*modsecurityv1.ConfigResponse, error) {
	content, path, err := s.cfg.GetRules()
	if err != nil {
		if errors.Is(err, modsec.ErrConfigNotFound) {
			return nil, status.Error(codes.NotFound, "rules.conf not found")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &modsecurityv1.ConfigResponse{Content: content, FilePath: path}, nil
}

// ListRules parses rules.conf and returns structured items.
// A missing rules.conf propagates as Internal (matching Python's unhandled path).
func (s *Service) ListRules(ctx context.Context, _ *modsecurityv1.Empty2) (*modsecurityv1.ListRulesResponse, error) {
	items, err := s.cfg.ListRules()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	out := make([]*modsecurityv1.RuleItem, 0, len(items))
	for _, item := range items {
		out = append(out, &modsecurityv1.RuleItem{
			Id:       item.ID,
			Rule:     item.Rule,
			Message:  item.Message,
			Phase:    int64PtrToWrapper(item.Phase),
			Action:   item.Action,
			Severity: int64PtrToWrapper(item.Severity),
		})
	}
	return &modsecurityv1.ListRulesResponse{Rules: out}, nil
}

// UpdateConfig overwrites modsecurity.conf with the supplied content.
func (s *Service) UpdateConfig(ctx context.Context, req *modsecurityv1.ConfigUpdate) (*modsecurityv1.ConfigResponse, error) {
	path, err := s.cfg.UpdateConfig(req.Content)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &modsecurityv1.ConfigResponse{Content: req.Content, FilePath: path}, nil
}

// UpdateRules overwrites rules.conf with the supplied content.
func (s *Service) UpdateRules(ctx context.Context, req *modsecurityv1.ConfigUpdate) (*modsecurityv1.ConfigResponse, error) {
	path, err := s.cfg.UpdateRules(req.Content)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &modsecurityv1.ConfigResponse{Content: req.Content, FilePath: path}, nil
}

// AddRule appends a single SecRule to rules.conf.
// Returns InvalidArgument if the rule has no id field; Internal on I/O error.
func (s *Service) AddRule(ctx context.Context, req *modsecurityv1.RuleCreate) (*modsecurityv1.RuleResponse, error) {
	id, _, err := s.cfg.AddRule(req.Rule)
	if err != nil {
		if errors.Is(err, modsec.ErrInvalidRule) {
			return nil, status.Error(codes.InvalidArgument, "Rule must contain an id")
		}
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &modsecurityv1.RuleResponse{
		Rule:    req.Rule,
		Id:      wrapperspb.Int64(id),
		Success: true,
		Message: "Rule added successfully",
	}, nil
}

// DeleteRule removes the rule with the given id from rules.conf.
// Returns NotFound if no matching rule exists.
func (s *Service) DeleteRule(ctx context.Context, req *modsecurityv1.DeleteRuleRequest) (*emptypb.Empty, error) {
	deleted, err := s.cfg.DeleteRule(req.RuleId)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	if !deleted {
		return nil, status.Error(codes.NotFound, fmt.Sprintf("Rule with id %d not found", req.RuleId))
	}
	return &emptypb.Empty{}, nil
}

// Reload asks Angie to re-read its config.
// Always returns a 200-status body (never a gRPC error), matching Python.
func (s *Service) Reload(ctx context.Context, _ *modsecurityv1.Empty2) (*modsecurityv1.ReloadResponse, error) {
	ok, msg := s.reloader.ReloadVerbose(ctx)
	return &modsecurityv1.ReloadResponse{Success: ok, Message: msg}, nil
}

// int64PtrToWrapper converts a nullable int64 pointer to a wrapperspb.Int64Value.
func int64PtrToWrapper(p *int64) *wrapperspb.Int64Value {
	if p == nil {
		return nil
	}
	return wrapperspb.Int64(*p)
}
