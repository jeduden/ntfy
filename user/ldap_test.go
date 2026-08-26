package user

import (
	"errors"
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
