package user

import (
	"regexp"
	"strings"
	"sync"
	"time"

	"heckel.io/ntfy/v2/db"
	"heckel.io/ntfy/v2/log"
)

// accessCache is an in-memory index over the entire user_access table.
//
// exact[username][escapedTopic] returns the matching entry in O(1) for the common
// case where the requested topic appears verbatim in some rule. The key is the
// stored form of the topic (i.e. with \_ escapes), so Lookup escapes incoming
// topics through escapeUnderscore before probing.
//
// pattern[username] is the linear-scan list of %-bearing rules for that user.
// Walked per request; trivially small in practice. Wildcards are NOT u_everyone-
// only -- any user can create them.
type accessCache struct {
	exact   map[string]map[string]aclEntry
	pattern map[string][]aclEntry
	seq     uint64       // Bumped on every reload; lets a full reload detect a per-user reload that raced its scan
	mu      sync.RWMutex // Protect exact, pattern, and seq
}

// testHookReloadScanned, if non-nil, is invoked by Reload after the DB scan but
// before the result is applied. Tests use it to inject a concurrent mutation
// into the full-reload race window; it is always nil in production.
var testHookReloadScanned func()

// aclEntry mirrors one user_access row. length feeds better()'s "longer
// pattern wins" tie-break; the stored topic/pattern string itself is not kept
// on the entry (the exact map already keys on it; surfacing wildcard "topics"
// like "up%" alongside real ones would invite misuse). pattern is the
// compiled regex form of the LIKE pattern; nil for exact entries. sourceRank is
// the precomputed provenance priority (see accessSourceRank), used by better()
// to break ties between equally specific rules.
type aclEntry struct {
	length     int
	pattern    *regexp.Regexp
	read       bool
	write      bool
	sourceRank int
}

// accessSourceRank maps a user_access.source to its authorization priority, lower
// winning. A manual grant (CLI/API/reservation) is an explicit operator decision and
// outranks declarative policy; auth-access (config) outranks auth-ldap-access (ldap).
// This is a tie-break below pattern length, so a more specific rule still wins first.
func accessSourceRank(source string) int {
	switch source {
	case accessSourceManual:
		return 0
	case accessSourceConfig:
		return 1
	default: // accessSourceLDAP, and any unknown value, rank last
		return 2
	}
}

func newAccessCache() *accessCache {
	return &accessCache{
		exact:   make(map[string]map[string]aclEntry),
		pattern: make(map[string][]aclEntry),
	}
}

// Lookup returns the effective (read, write, found) permission for the given
// (username, topic), preserving the priority ordering of the SQL query:
//  1. specific user beats Everyone
//  2. longer pattern beats shorter (more specific wins)
//  3. more authoritative source wins at equal length (manual > config > ldap)
//  4. write beats read at equal length and source (write is "stronger")
func (c *accessCache) Lookup(username, topic string) (read, write, found bool) {
	escapedTopic := escapeUnderscore(topic)
	c.mu.RLock()
	if username != Everyone {
		if entry, found := c.lookupNoLock(username, topic, escapedTopic); found {
			c.mu.RUnlock()
			maybeLogACLDecision(username, username, topic, entry.read, entry.write)
			return entry.read, entry.write, true
		}
	}
	if entry, found := c.lookupNoLock(Everyone, topic, escapedTopic); found {
		c.mu.RUnlock()
		maybeLogACLDecision(username, Everyone, topic, entry.read, entry.write)
		return entry.read, entry.write, true
	}
	c.mu.RUnlock()
	maybeLogACLDecision(username, "", topic, false, false)
	return false, false, false
}

// Reload scans (user_name, topic, read, write) rows and merges them into the
// cache. With no usernames the cache is replaced wholesale; otherwise the
// query is invoked with those usernames as positional args and only the
// listed users' slices are touched (a username absent from the result drops
// them from both maps). Runs against the primary so a reload after a
// mutation sees the just-written rows.
//
// Since Reload can be triggered from different places and for different scopes (full
// and user-specific), the function may cause races and lost-updates. This is solved
// with the sequence number.
func (c *accessCache) Reload(d *db.DB, query string, usernames ...string) error {
	started := time.Now()
	scope := "full"
	if len(usernames) > 0 {
		scope = "users=" + strings.Join(usernames, ",")
	}
	// Read the sequence number before the SQL query so we can detect races later
	c.mu.RLock()
	seqBefore := c.seq
	c.mu.RUnlock()
	args := make([]any, len(usernames))
	for i, u := range usernames {
		args[i] = u
	}
	// Query the database for all ACL entries
	rows, err := d.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	exacts := make(map[string]map[string]aclEntry)
	patterns := make(map[string][]aclEntry)
	updatedEntries := 0
	for rows.Next() {
		var username, escapedTopic, source string
		var read, write bool
		if err := rows.Scan(&username, &escapedTopic, &read, &write, &source); err != nil {
			return err
		}
		entry, hasWildcard, err := toACLEntry(escapedTopic, read, write, source)
		if err != nil {
			return err
		}
		if hasWildcard {
			patterns[username] = append(patterns[username], entry)
		} else {
			if exacts[username] == nil {
				exacts[username] = make(map[string]aclEntry)
			}
			exacts[username][escapedTopic] = entry
		}
		updatedEntries++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if testHookReloadScanned != nil {
		testHookReloadScanned()
	}
	// Replace or update the internal maps
	c.mu.Lock()
	if len(usernames) == 0 {
		if c.seq != seqBefore {
			c.mu.Unlock()
			log.Tag(tag).
				Field("reload_scope", scope).
				Field("duration_ms", time.Since(started).Milliseconds()).
				Warn("ACL cache reload skipped due to race")
			return nil
		}
		c.exact = exacts
		c.pattern = patterns
	} else {
		for _, u := range usernames {
			if e, ok := exacts[u]; ok {
				c.exact[u] = e
			} else {
				delete(c.exact, u)
			}
			if p, ok := patterns[u]; ok {
				c.pattern[u] = p
			} else {
				delete(c.pattern, u)
			}
		}
	}
	c.seq++
	c.mu.Unlock()
	log.Tag(tag).
		Field("reload_scope", scope).
		Field("updated_entries", updatedEntries).
		Field("duration_ms", time.Since(started).Milliseconds()).
		Debug("ACL cache reloaded")
	return nil
}

// lookupNoLock returns the highest-priority entry for a single user. When
// more than one of that user's rules matches the requested topic, the winner
// is chosen by:
//
//  1. longer stored pattern beats shorter (a more specific rule wins over a
//     more general one)
//  2. at equal length, the more authoritative source wins (manual > config > ldap)
//  3. at equal length and source, write beats read (a stronger permission wins)
//
// Exact and wildcard rules are ranked together under the same criteria, so
// an exact "foo" (length 3) beats a wildcard "f%" (length 2), but a wildcard
// "foo%" (length 4) beats an exact "foo" (length 3).
func (c *accessCache) lookupNoLock(username, topic, escapedTopic string) (*aclEntry, bool) {
	var best aclEntry
	var found bool
	if exact, exists := c.exact[username]; exists {
		if entry, exists := exact[escapedTopic]; exists {
			best, found = entry, true
		}
	}
	for _, pattern := range c.pattern[username] {
		if !pattern.pattern.MatchString(topic) {
			continue
		} else if !found || better(pattern, best) {
			best, found = pattern, true
		}
	}
	return &best, found
}

// toACLEntry builds an aclEntry from one user_access row's values. The
// isWildcard return tells the caller which storage slot the entry belongs in:
// the per-user wildcard slice if true, the per-user exact map if false.
// Wildcards have their LIKE pattern pre-compiled into entry.pattern; exact
// entries leave entry.pattern nil.
func toACLEntry(escapedTopic string, read, write bool, source string) (entry aclEntry, hasWildcard bool, err error) {
	entry = aclEntry{
		length:     len(escapedTopic),
		read:       read,
		write:      write,
		sourceRank: accessSourceRank(source),
	}
	if !strings.Contains(escapedTopic, "%") {
		return entry, false, nil
	}
	pattern, err := compileLikeToRegex(escapedTopic)
	if err != nil {
		return entry, true, err
	}
	entry.pattern = pattern
	return entry, true, nil
}

// better implements the (length DESC, sourceRank ASC, write DESC) tie-break used by
// the query's ORDER BY for entries owned by the same user: a longer (more specific)
// pattern wins; at equal length the more authoritative source wins (manual > config >
// ldap); at equal length and source, write beats read.
func better(a, b aclEntry) bool {
	if a.length != b.length {
		return a.length > b.length
	} else if a.sourceRank != b.sourceRank {
		return a.sourceRank < b.sourceRank
	} else if a.write != b.write {
		return a.write
	}
	return false
}

// compileLikeToRegex converts a stored ntfy LIKE pattern into an equivalent Go
// regexp. In ntfy's stored form, % is the only wildcard (translated from *) and
// \_ is a literal underscore; no other backslashes occur. Topics themselves are
// restricted to [A-Za-z0-9_-] (see AllowedTopic), so neither % nor stray
// backslashes appear in user-supplied input.
func compileLikeToRegex(pattern string) (*regexp.Regexp, error) {
	var sb strings.Builder
	sb.WriteString("^")
	i := 0
	for i < len(pattern) {
		switch {
		case pattern[i] == '\\' && i+1 < len(pattern) && pattern[i+1] == '_':
			sb.WriteString(regexp.QuoteMeta("_"))
			i += 2
		case pattern[i] == '%':
			sb.WriteString(".*")
			i++
		default:
			sb.WriteString(regexp.QuoteMeta(string(pattern[i])))
			i++
		}
	}
	sb.WriteString("$")
	return regexp.Compile(sb.String())
}

// maybeLogACLDecision logs an ACL lookup result
func maybeLogACLDecision(requestUser, matchedUser, topic string, read, write bool) {
	ev := log.Tag(tag).
		Field("user_name", requestUser).
		Field("topic", topic).
		Field("read", read).
		Field("write", write)
	if !ev.IsTrace() {
		return
	}
	if matchedUser == "" {
		ev.Trace("ACL no match")
		return
	}
	ev.Field("matched_user", matchedUser).Trace("ACL match")
}
