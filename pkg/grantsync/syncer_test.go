package grantsync

import (
	"testing"
)

func TestRolesEqual(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want bool
	}{
		{"same order", []string{"admin", "viewer"}, []string{"admin", "viewer"}, true},
		{"different order", []string{"viewer", "admin"}, []string{"admin", "viewer"}, true},
		{"different length", []string{"admin"}, []string{"admin", "viewer"}, false},
		{"empty both", []string{}, []string{}, true},
		{"one empty", []string{"admin"}, []string{}, false},
		{"nil vs empty", nil, []string{}, true},
		{"nil vs nil", nil, nil, true},
		{"single same", []string{"admin"}, []string{"admin"}, true},
		{"single different", []string{"admin"}, []string{"viewer"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rolesEqual(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("rolesEqual(%v, %v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
