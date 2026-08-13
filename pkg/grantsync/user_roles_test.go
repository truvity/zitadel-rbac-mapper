package grantsync

import (
	"reflect"
	"testing"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user"
)

func TestGrantEntries(t *testing.T) {
	got := grantEntries([]*user.UserGrant{
		{ProjectName: "cluster-devel", RoleKeys: []string{"ci-truvity-bar:deployer", ""}},
		{ProjectName: "", RoleKeys: []string{"ignored:role"}},
		nil,
	})

	want := []string{"cluster-devel:ci-truvity-bar:deployer"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("grantEntries = %v, want %v", got, want)
	}

	if empty := grantEntries(nil); empty == nil || len(empty) != 0 {
		t.Errorf("grantEntries(nil) must be an empty non-nil slice, got %#v", empty)
	}
}
