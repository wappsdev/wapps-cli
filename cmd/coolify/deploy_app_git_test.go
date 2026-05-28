package coolify

import "testing"

func TestShouldDeferDeploy(t *testing.T) {
	cases := []struct {
		name           string
		instantDeploy  bool
		buildArgs      []string
		wantDefer      bool
	}{
		{
			name:          "no build args, instant deploy → no defer",
			instantDeploy: true,
			buildArgs:     nil,
			wantDefer:     false,
		},
		{
			name:          "build args + instant deploy → defer (must set args before build)",
			instantDeploy: true,
			buildArgs:     []string{"VERSION=1.0"},
			wantDefer:     true,
		},
		{
			name:          "build args but operator already chose no instant → no defer needed",
			instantDeploy: false,
			buildArgs:     []string{"VERSION=1.0"},
			wantDefer:     false,
		},
		{
			name:          "neither → no defer",
			instantDeploy: false,
			buildArgs:     nil,
			wantDefer:     false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shouldDeferDeploy(c.instantDeploy, c.buildArgs); got != c.wantDefer {
				t.Errorf("got %v, want %v", got, c.wantDefer)
			}
		})
	}
}
