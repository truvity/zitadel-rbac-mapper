package grantsync

import (
	"context"

	"github.com/zitadel/zitadel-go/v3/pkg/client/middleware"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user"
)

// UserRoleEntries lists the user's grants via the Management API and
// flattens them into "{projectName}:{roleKey}" claim entries. The
// machine-user enrichment's fallback: machine token flows (jwt-bearer)
// deliver Actions payloads WITHOUT user_grants even when grants exist
// and resolve into the token's native roles claim — observed live
// 2026-08-13 (gitops INF-452 prototype), so the mapper asks the
// Management API directly.
// orgID scopes the Management API call to the user's organization —
// without it the API defaults to the service user's own org and finds
// nothing for users of other orgs (the Platform org's ci-* users;
// observed live 2026-08-13: empty spine despite a live grant).
func (s *Syncer) UserRoleEntries(ctx context.Context, userID, orgID string) ([]string, error) {
	if orgID != "" {
		ctx = middleware.SetOrgID(ctx, orgID)
	}

	grants, err := s.listUserGrants(ctx, userID)
	if err != nil {
		return nil, err
	}

	return grantEntries(grants), nil
}

// grantEntries flattens Management API grants into claim entries;
// grants without a project name or role keys contribute nothing.
func grantEntries(grants []*user.UserGrant) []string {
	entries := []string{}

	for _, g := range grants {
		name := g.GetProjectName()
		if name == "" {
			continue
		}

		for _, role := range g.GetRoleKeys() {
			if role == "" {
				continue
			}

			entries = append(entries, name+":"+role)
		}
	}

	return entries
}
