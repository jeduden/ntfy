package user

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ldapUserPasswordHash is the sentinel value stored in the "pass" column for users whose
// password is verified against an external LDAP server (e.g. LLDAP) via a bind, rather than
// against a local bcrypt hash. It is intentionally not a valid bcrypt hash, so a local
// password comparison for such a user always fails; authentication for these users goes
// exclusively through the LDAP bind path in Manager.Authenticate. LDAP users are stored as
// non-provisioned rows, so the declarative provisioning reconciler never deletes them.
const ldapUserPasswordHash = "$ldap$external-auth"

// DefaultLDAPTimeout is the default dial/bind timeout for LDAP authentication.
const DefaultLDAPTimeout = 5 * time.Second

// LDAPConfig holds the configuration for authenticating users against an external LDAP server
// (e.g. LLDAP) via a bind. Authentication is enabled only when URL is non-empty.
type LDAPConfig struct {
	URL            string        // LDAP server URL, e.g. "ldap://lldap.example:3890" or "ldaps://lldap.example:636"
	BindDNTemplate string        // Bind DN with a single %s placeholder for the username, e.g. "uid=%s,ou=people,dc=example,dc=com"
	StartTLS       bool          // Whether to issue StartTLS on a plain ldap:// connection before binding
	DefaultRole    Role          // Role assigned to LDAP users auto-created on first successful login (defaults to RoleUser)
	Timeout        time.Duration // Dial/bind timeout; defaults to DefaultLDAPTimeout when zero or negative
	Access         []Grant       // Topic ACL grants seeded for an LDAP user when its shadow row is created on first login
}

// ldapAuther verifies a username/password pair against an external LDAP server. It is an
// interface so tests can substitute an in-memory fake for a real LDAP server.
type ldapAuther interface {
	// BindUser attempts to bind to the LDAP server as the given user. It returns nil if the
	// credentials are valid, and a non-nil error otherwise.
	BindUser(username, password string) error
}

// ldapClient is the production ldapAuther, backed by github.com/go-ldap/ldap/v3.
type ldapClient struct {
	config *LDAPConfig
}

// newLDAPClient builds an ldapClient from the given config, applying defaults for the role and
// timeout. It does not open a connection; connections are opened per BindUser call.
func newLDAPClient(config *LDAPConfig) *ldapClient {
	if config.DefaultRole == "" {
		config.DefaultRole = RoleUser
	}
	if config.Timeout <= 0 {
		config.Timeout = DefaultLDAPTimeout
	}
	return &ldapClient{config: config}
}

// BindUser dials the configured LDAP server and attempts a simple bind as the given user,
// using BindDNTemplate to form the bind DN. A successful bind proves the password is valid.
// The connection is closed before returning.
func (c *ldapClient) BindUser(username, password string) error {
	if username == "" || password == "" {
		return ErrUnauthenticated
	}
	conn, err := ldap.DialURL(c.config.URL, ldap.DialWithDialer(&net.Dialer{Timeout: c.config.Timeout}))
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetTimeout(c.config.Timeout)
	if c.config.StartTLS {
		// go-ldap's StartTLS calls tls.Client, which (unlike tls.Dial) does not auto-populate
		// ServerName; without it the handshake fails with "either ServerName or InsecureSkipVerify
		// must be specified". Derive it from the configured URL so the server cert is verified.
		host, err := ldapHost(c.config.URL)
		if err != nil {
			return err
		}
		if err := conn.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	// Escape the username before substituting it into the bind DN template so a username containing
	// a DN metacharacter (e.g. '+', which AllowedUsername permits) cannot alter the DN structure.
	return conn.Bind(fmt.Sprintf(c.config.BindDNTemplate, ldap.EscapeDN(username)), password)
}

// ldapHost returns the hostname component of an LDAP URL, used as the TLS ServerName for StartTLS.
func ldapHost(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	return u.Hostname(), nil
}
