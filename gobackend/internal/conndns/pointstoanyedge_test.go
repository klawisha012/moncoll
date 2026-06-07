package conndns

import (
	"context"
	"testing"
)

type fakeRes struct {
	ips map[string][]string
}

func (f fakeRes) LookupTXT(_ context.Context, _ string) ([]string, error) { return nil, nil }
func (f fakeRes) LookupHost(_ context.Context, host string) ([]string, error) {
	return f.ips[host], nil
}

func TestPointsToAnyEdge(t *testing.T) {
	r := fakeRes{ips: map[string][]string{"d.test": {"1.1.1.1", "2.2.2.2"}}}
	if res := PointsToAnyEdge(context.Background(), r, "d.test", []string{"2.2.2.2", "3.3.3.3"}); !res.FlippedToEdge {
		t.Fatal("expected FlippedToEdge=true (intersection)")
	}
	if res := PointsToAnyEdge(context.Background(), r, "d.test", []string{"9.9.9.9"}); res.FlippedToEdge {
		t.Fatal("expected FlippedToEdge=false (no intersection)")
	}
	if res := PointsToAnyEdge(context.Background(), r, "d.test", nil); res.FlippedToEdge {
		t.Fatal("expected FlippedToEdge=false (no edge IPs)")
	}
}
