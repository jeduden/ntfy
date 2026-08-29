package user

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// fakeLDAP is an in-memory ldapAuther for tests. It accepts the username/password pairs in creds
// and counts bind attempts, so tests can assert that local users never trigger an LDAP bind.
type fakeLDAP struct {
	creds map[string]string
	binds int
}

func (f *fakeLDAP) BindUser(username, password string) error {
	f.binds++
	if pw, ok := f.creds[username]; ok && pw == password {
		return nil
	}
	return errors.New("ldap: invalid credentials")
}

func TestManager_Authenticate_LDAP_CreatesShadowUserOnFirstLogin(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newManager newManagerFunc) {
		a := newTestManager(t, newManager, PermissionDenyAll)
		a.ldap = &fakeLDAP{creds: map[string]string{"phil": "secret"}}

		// Unknown user authenticates via LDAP -> a local shadow user is created
		u, err := a.Authenticate("phil", "secret")
		require.Nil(t, err)
		require.Equal(t, "phil", u.Name)
		require.Equal(t, RoleUser, u.Role)
		require.False(t, u.Provisioned) // must be non-provisioned so the reconciler never sweeps it
		require.Equal(t, ldapUserPasswordHash, u.Hash)

		// The shadow row persists and is reused on the next login (no duplicate)
		u2, err := a.Authenticate("phil", "secret")
		require.Nil(t, err)
		require.Equal(t, u.ID, u2.ID)

		// With LDAP disabled, the sentinel hash is unusable: local password auth cannot succeed
		a.ldap = nil
		_, err = a.Authenticate("phil", "secret")
		require.Equal(t, ErrUnauthenticated, err)
	})
}

func TestManager_Authenticate_LDAP_WrongPasswordCreatesNoUser(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newManager newManagerFunc) {
		a := newTestManager(t, newManager, PermissionDenyAll)
		a.ldap = &fakeLDAP{creds: map[string]string{"phil": "secret"}}

		_, err := a.Authenticate("phil", "wrong")
		require.Equal(t, ErrUnauthenticated, err)

		// A failed LDAP bind must not create a shadow user
		_, err = a.userByNameOrEmail("phil")
		require.Error(t, err)
	})
}

func TestManager_Authenticate_LDAP_LocalUserBypassesLDAP(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newManager newManagerFunc) {
		a := newTestManager(t, newManager, PermissionDenyAll)
		fake := &fakeLDAP{creds: map[string]string{"phil": "ldap-pw"}}
		a.ldap = fake
		require.Nil(t, a.AddUser("phil", "local-pw", RoleUser, false))

		// A real local user authenticates against the local hash; LDAP is never consulted
		u, err := a.Authenticate("phil", "local-pw")
		require.Nil(t, err)
		require.Equal(t, "phil", u.Name)
		require.Equal(t, 0, fake.binds)

		// A wrong local password fails and must NOT fall back to LDAP, even though the fake would
		// accept "ldap-pw" for this username. This prevents an LDAP identity from overriding a
		// locally-managed service account.
		_, err = a.Authenticate("phil", "ldap-pw")
		require.Equal(t, ErrUnauthenticated, err)
		require.Equal(t, 0, fake.binds)
	})
}

func TestManager_Authenticate_LDAPUser_SurvivesProvisioningReconcile(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newManager newManagerFunc) {
		conf := &Config{
			DefaultAccess:       PermissionDenyAll,
			ProvisionEnabled:    true,
			BcryptCost:          bcrypt.MinCost,
			QueueWriterInterval: DefaultUserStatsQueueWriterInterval,
			Users: []*User{
				{Name: "admin", Hash: "$2a$10$YLiO8U21sX1uhZamTLJXHuxgVC0Z/GKISibrKCLohPgtG7yIxSk4C", Role: RoleAdmin},
			},
		}
		a := newTestManagerFromConfig(t, newManager, conf)
		a.ldap = &fakeLDAP{creds: map[string]string{"phil": "secret"}}

		_, err := a.Authenticate("phil", "secret")
		require.Nil(t, err)

		// Re-run declarative provisioning (which deletes provisioned users absent from the config).
		// The non-provisioned LDAP user must survive.
		require.Nil(t, a.maybeProvisionUsersAccessAndTokens())

		u, err := a.userByNameOrEmail("phil")
		require.Nil(t, err)
		require.Equal(t, "phil", u.Name)
		require.False(t, u.Provisioned)
	})
}

func TestManager_Authenticate_LDAP_DefaultRoleAdmin(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newManager newManagerFunc) {
		a := newTestManager(t, newManager, PermissionDenyAll)
		a.config.LDAP = &LDAPConfig{DefaultRole: RoleAdmin}
		a.ldap = &fakeLDAP{creds: map[string]string{"boss": "pw"}}

		u, err := a.Authenticate("boss", "pw")
		require.Nil(t, err)
		require.Equal(t, RoleAdmin, u.Role)
	})
}

func TestManager_Authenticate_LDAP_AppliesAccessGrants(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newManager newManagerFunc) {
		a := newTestManager(t, newManager, PermissionDenyAll)
		a.config.LDAP = &LDAPConfig{Access: []Grant{
			{TopicPattern: "alerts", Permission: PermissionRead},
			{TopicPattern: "myteam", Permission: PermissionReadWrite},
		}}
		a.ldap = &fakeLDAP{creds: map[string]string{"phil": "secret"}}

		// On first login the configured grants are applied to the freshly-created shadow user
		u, err := a.Authenticate("phil", "secret")
		require.Nil(t, err)
		require.Nil(t, a.Authorize(u, "alerts", PermissionRead))
		require.Equal(t, ErrUnauthorized, a.Authorize(u, "alerts", PermissionWrite))
		require.Nil(t, a.Authorize(u, "myteam", PermissionWrite))
		require.Nil(t, a.Authorize(u, "myteam", PermissionRead))
		require.Equal(t, ErrUnauthorized, a.Authorize(u, "other", PermissionRead))

		grants, err := a.Grants("phil")
		require.Nil(t, err)
		require.Len(t, grants, 2)
		require.Equal(t, accessSourceLDAP, grants[0].Source)
		require.Equal(t, "LDAP config", grants[0].SourceLabel()) // shown by `ntfy access`, distinct from auth-access
	})
}

func TestManager_Authenticate_LDAP_AccessReconciledAtStartup(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newManager newManagerFunc) {
		a := newTestManager(t, newManager, PermissionDenyAll)
		a.config.LDAP = &LDAPConfig{Access: []Grant{
			{TopicPattern: "alerts", Permission: PermissionRead},
		}}
		a.ldap = &fakeLDAP{creds: map[string]string{"phil": "secret"}}

		// First login materializes the configured grant (as source='ldap')
		_, err := a.Authenticate("phil", "secret")
		require.Nil(t, err)
		grants, err := a.Grants("phil")
		require.Nil(t, err)
		require.Len(t, grants, 1)
		require.Equal(t, "alerts", grants[0].TopicPattern)

		// An admin adds a manual (source='manual') grant out-of-band, as the CLI would
		require.Nil(t, a.AllowAccess("phil", "other", PermissionReadWrite))

		// The config changes (which requires a restart): 'alerts' removed, 'myteam:rw' added.
		a.config.LDAP.Access = []Grant{{TopicPattern: "myteam", Permission: PermissionReadWrite}}

		// A restart rebuilds all source='ldap' rows from config: 'alerts' swept, 'myteam' created,
		// and the admin's manual 'other' grant left untouched.
		require.Nil(t, a.maybeReconcileLDAPAccess())
		grants, err = a.Grants("phil")
		require.Nil(t, err)
		patterns := make(map[string]Permission, len(grants))
		for _, g := range grants {
			patterns[g.TopicPattern] = g.Permission
		}
		require.Len(t, grants, 2)
		require.Equal(t, PermissionReadWrite, patterns["myteam"])
		require.Equal(t, PermissionReadWrite, patterns["other"]) // manual grant survives the reconcile
		require.NotContains(t, patterns, "alerts")               // removed from config -> swept
	})
}

func TestManager_Authenticate_LDAP_ReturningLoginDoesNotReapplyConfig(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newManager newManagerFunc) {
		a := newTestManager(t, newManager, PermissionDenyAll)
		a.config.LDAP = &LDAPConfig{Access: []Grant{{TopicPattern: "alerts", Permission: PermissionRead}}}
		a.ldap = &fakeLDAP{creds: map[string]string{"phil": "secret"}}

		_, err := a.Authenticate("phil", "secret")
		require.Nil(t, err)

		// Admin edits the stored grant via the CLI, then the config changes WITHOUT a restart.
		require.Nil(t, a.AllowAccess("phil", "alerts", PermissionReadWrite))
		a.config.LDAP.Access = []Grant{{TopicPattern: "alerts", Permission: PermissionRead}}

		// A returning login must not touch the DB: the admin's rw override stands until the next restart.
		_, err = a.Authenticate("phil", "secret")
		require.Nil(t, err)
		grants, err := a.Grants("phil")
		require.Nil(t, err)
		require.Len(t, grants, 1)
		require.Equal(t, PermissionReadWrite, grants[0].Permission) // unchanged by the login
	})
}

func TestManager_Authenticate_LDAP_ReconcileNeverClobbersManualGrant(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newManager newManagerFunc) {
		a := newTestManager(t, newManager, PermissionDenyAll)
		a.config.LDAP = &LDAPConfig{Access: []Grant{{TopicPattern: "ops", Permission: PermissionRead}}}
		a.ldap = &fakeLDAP{creds: map[string]string{"phil": "secret"}}

		// First login seeds ops:ro as an ldap grant
		_, err := a.Authenticate("phil", "secret")
		require.Nil(t, err)

		// An admin overrides the SAME topic with a manual read-write grant (as `ntfy access` would).
		// This upserts the (phil, ops) row to source='manual'.
		require.Nil(t, a.AllowAccess("phil", "ops", PermissionReadWrite))

		// A startup reconcile must NOT downgrade or reclaim that topic: the ldap insert for 'ops'
		// hits the manual row and does nothing, so the admin's rw grant stands.
		require.Nil(t, a.maybeReconcileLDAPAccess())
		grants, err := a.Grants("phil")
		require.Nil(t, err)
		require.Len(t, grants, 1)
		require.Equal(t, "ops", grants[0].TopicPattern)
		require.Equal(t, PermissionReadWrite, grants[0].Permission) // manual rw preserved, not ldap ro
		require.False(t, grants[0].Provisioned)                     // still source='manual'
	})
}

func TestManager_Authenticate_LDAP_ReconcilePreservesReservation(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newManager newManagerFunc) {
		a := newTestManager(t, newManager, PermissionDenyAll)
		a.config.LDAP = &LDAPConfig{Access: []Grant{{TopicPattern: "team", Permission: PermissionRead}}}
		a.ldap = &fakeLDAP{creds: map[string]string{"phil": "secret"}}

		_, err := a.Authenticate("phil", "secret")
		require.Nil(t, err)

		// phil reserves the same topic 'team' (owner_user_id = phil, source='manual')
		require.Nil(t, a.AddReservation("phil", "team", PermissionDenyAll, 0))
		reservations, err := a.Reservations("phil")
		require.Nil(t, err)
		require.Len(t, reservations, 1)

		// A startup reconcile must not destroy the reservation by nulling owner_user_id / flipping source
		require.Nil(t, a.maybeReconcileLDAPAccess())
		reservations, err = a.Reservations("phil")
		require.Nil(t, err)
		require.Len(t, reservations, 1)
		require.Equal(t, "team", reservations[0].Topic)
	})
}

func TestManager_Authenticate_LDAP_EmptyConfigSweepsLDAPGrantsAtStartup(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newManager newManagerFunc) {
		a := newTestManager(t, newManager, PermissionDenyAll)
		a.config.LDAP = &LDAPConfig{Access: []Grant{
			{TopicPattern: "alerts", Permission: PermissionRead},
		}}
		a.ldap = &fakeLDAP{creds: map[string]string{"phil": "secret"}}

		_, err := a.Authenticate("phil", "secret")
		require.Nil(t, err)
		grants, err := a.Grants("phil")
		require.Nil(t, err)
		require.Len(t, grants, 1)

		// Emptying auth-ldap-access sweeps the user's ldap grants at the next startup reconcile
		a.config.LDAP.Access = nil
		require.Nil(t, a.maybeReconcileLDAPAccess())
		grants, err = a.Grants("phil")
		require.Nil(t, err)
		require.Len(t, grants, 0)
	})
}

func TestManager_Authorize_ManualGrantBeatsLDAPAtEqualLength(t *testing.T) {
	forEachBackend(t, func(t *testing.T, newManager newManagerFunc) {
		// Writer (cache ON), LDAP configured: first login seeds alerts:rw as source='ldap'.
		writer := newManager(&Config{
			DefaultAccess:      PermissionDenyAll,
			BcryptCost:         bcrypt.MinCost,
			AccessCacheEnabled: true,
			LDAP:               &LDAPConfig{Access: []Grant{{TopicPattern: "alerts", Permission: PermissionReadWrite}}},
		})
		t.Cleanup(func() { writer.Close() })
		writer.ldap = &fakeLDAP{creds: map[string]string{"phil": "secret"}}

		u, err := writer.Authenticate("phil", "secret")
		require.Nil(t, err)
		// An admin restricts the topic with a manual, equal-length ("alert%" == 6 == "alerts")
		// read-only wildcard. Only source priority (manual > ldap), applied before write-beats-read,
		// lets this ro rule win over the seeded ldap rw rule.
		require.Nil(t, writer.AllowAccess("phil", "alert*", PermissionRead))

		// Cache path
		require.Nil(t, writer.Authorize(u, "alerts", PermissionRead))
		require.Equal(t, ErrUnauthorized, writer.Authorize(u, "alerts", PermissionWrite))

		// SQL path: a second manager on the same backend with the cache OFF must agree
		reader := newManager(&Config{
			DefaultAccess:      PermissionDenyAll,
			BcryptCost:         bcrypt.MinCost,
			AccessCacheEnabled: false,
		})
		t.Cleanup(func() { reader.Close() })
		ru, err := reader.userByNameOrEmail("phil")
		require.Nil(t, err)
		require.Nil(t, reader.Authorize(ru, "alerts", PermissionRead))
		require.Equal(t, ErrUnauthorized, reader.Authorize(ru, "alerts", PermissionWrite))
	})
}

func TestManager_Authenticate_LDAP_DBErrorFailsClosed(t *testing.T) {
	// A non-ErrUserNotFound error from the user lookup (here: a closed database) must fail closed and
	// never consult LDAP. Otherwise an attacker who can bind as a same-named LDAP user could hijack a
	// local account during a transient DB failure. Uses a file-backed manager (no forEachBackend) so
	// closing the DB does not race the shared cleanup.
	a := newTestManagerFromFile(t, filepath.Join(t.TempDir(), "user.db"), "", PermissionDenyAll, bcrypt.MinCost, DefaultUserStatsQueueWriterInterval)
	fake := &fakeLDAP{creds: map[string]string{"phil": "ldap-pw"}}
	a.ldap = fake
	require.Nil(t, a.AddUser("phil", "local-pw", RoleUser, false))

	require.Nil(t, testDB(a).Close()) // force a real (non-NotFound) lookup error

	_, err := a.Authenticate("phil", "ldap-pw")
	require.Equal(t, ErrUnauthenticated, err)
	require.Equal(t, 0, fake.binds) // must not fall through to LDAP on a lookup error
}

func TestLDAPHost(t *testing.T) {
	cases := []struct {
		url  string
		host string
	}{
		{"ldap://lldap.example:3890", "lldap.example"},
		{"ldaps://lldap.example", "lldap.example"},
		{"ldap://127.0.0.1:389", "127.0.0.1"},
		{"ldaps://[::1]:636", "::1"},
	}
	for _, c := range cases {
		host, err := ldapHost(c.url)
		require.Nil(t, err)
		require.Equal(t, c.host, host)
	}
}

func TestLDAPClient_NewClientDefaultsAndEmptyCredentials(t *testing.T) {
	c := newLDAPClient(&LDAPConfig{
		URL:            "ldap://localhost:3890",
		BindDNTemplate: "uid=%s,ou=people,dc=example,dc=com",
	})
	// Defaults are applied
	require.Equal(t, RoleUser, c.config.DefaultRole)
	require.Equal(t, DefaultLDAPTimeout, c.config.Timeout)

	// Empty credentials are rejected before any network call
	require.Equal(t, ErrUnauthenticated, c.BindUser("phil", ""))
	require.Equal(t, ErrUnauthenticated, c.BindUser("", "secret"))
}
