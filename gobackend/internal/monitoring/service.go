package monitoring

import (
	"context"

	"golang.org/x/sync/errgroup"

	monitoringv1 "github.com/zwarder/waf/gobackend/gen/monitoring/v1"
)

// containerSummary is the minimal container view the service needs.
type containerSummary struct {
	ID     string
	Name   string
	Status string
	Image  string
}

// dockerSource abstracts the Docker engine for testability.
type dockerSource interface {
	listProjectContainers(ctx context.Context) ([]containerSummary, error)
	containerStats(ctx context.Context, id string) ([]byte, error)
}

type Service struct {
	monitoringv1.UnimplementedMonitoringServiceServer
	docker dockerSource
}

func NewService(d dockerSource) *Service { return &Service{docker: d} }

func (s *Service) GetMetrics(ctx context.Context, _ *monitoringv1.GetMetricsRequest) (*monitoringv1.MetricsResponse, error) {
	containers, err := s.docker.listProjectContainers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*monitoringv1.ContainerMetrics, len(containers))
	g, gctx := errgroup.WithContext(ctx)
	for i, c := range containers {
		i, c := i, c
		g.Go(func() error {
			raw, statErr := s.docker.containerStats(gctx, c.ID)
			if statErr != nil {
				out[i] = toProto(ContainerMetrics{Name: c.Name})
				return nil
			}
			out[i] = toProto(statsToMetrics(c.Name, raw))
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return &monitoringv1.MetricsResponse{Containers: out}, nil
}

func (s *Service) ListContainers(ctx context.Context, _ *monitoringv1.ListContainersRequest) (*monitoringv1.ListContainersResponse, error) {
	containers, err := s.docker.listProjectContainers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*monitoringv1.ContainerInfo, len(containers))
	for i, c := range containers {
		out[i] = &monitoringv1.ContainerInfo{Id: c.ID, Name: c.Name, Status: c.Status, Image: c.Image}
	}
	return &monitoringv1.ListContainersResponse{Containers: out}, nil
}

func toProto(m ContainerMetrics) *monitoringv1.ContainerMetrics {
	return &monitoringv1.ContainerMetrics{
		Name: m.Name, Cpu: m.CPU, Memory: m.Memory,
		MemoryPercent: m.MemoryPercent, NetworkRx: m.NetworkRx, NetworkTx: m.NetworkTx,
	}
}
