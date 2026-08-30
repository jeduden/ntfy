package server

import (
	"errors"
	"heckel.io/ntfy/v2/user"
	"net/http"
	"net/netip"
	"time"
)

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request, v *visitor) error {
	return s.writeJSON(w, &apiVersionResponse{
		Version: s.config.BuildVersion,
		Commit:  s.config.BuildCommit,
		Date:    s.config.BuildDate,
	})
}

func (s *Server) handleUsersGet(w http.ResponseWriter, r *http.Request, v *visitor) error {
	users, err := s.userManager.Users()
	if err != nil {
		return err
	}
	grants, err := s.userManager.AllGrants()
	if err != nil {
		return err
	}
	usersResponse := make([]*apiUserResponse, len(users))
	for i, u := range users {
		tier := ""
		if u.Tier != nil {
			tier = u.Tier.Code
		}
		userGrants := make([]*apiUserGrantResponse, len(grants[u.ID]))
		for i, g := range grants[u.ID] {
			userGrants[i] = &apiUserGrantResponse{
				Topic:      g.TopicPattern,
				Permission: g.Permission.String(),
			}
		}
		usersResponse[i] = &apiUserResponse{
			Username: u.Name,
			Role:     string(u.Role),
			Tier:     tier,
			Grants:   userGrants,
		}
	}
	return s.writeJSON(w, usersResponse)
}

func (s *Server) handleUsersAdd(w http.ResponseWriter, r *http.Request, v *visitor) error {
	req, err := readJSONWithLimit[apiUserAddOrUpdateRequest](r.Body, jsonBodyBytesLimit, false)
	if err != nil {
		return err
	} else if !user.AllowedUsername(req.Username) || (req.Password == "" && req.Hash == "") {
		return errHTTPBadRequest.Wrap("username invalid, or password/password_hash missing")
	}
	u, err := s.userManager.User(req.Username)
	if err != nil && !errors.Is(err, user.ErrUserNotFound) {
		return err
	} else if u != nil {
		return errHTTPConflictUserExists
	}
	var tier *user.Tier
	if req.Tier != "" {
		tier, err = s.userManager.Tier(req.Tier)
		if errors.Is(err, user.ErrTierNotFound) {
			return errHTTPBadRequestTierInvalid
		} else if err != nil {
			return err
		}
	}
	password, hashed := req.Password, false
	if req.Hash != "" {
		password, hashed = req.Hash, true
	}
	if err := s.userManager.AddUser(req.Username, password, user.RoleUser, hashed); err != nil {
		return err
	}
	if tier != nil {
		if err := s.userManager.ChangeTier(req.Username, req.Tier); err != nil {
			return err
		}
	}
	return s.writeJSON(w, newSuccessResponse())
}

func (s *Server) handleUsersUpdate(w http.ResponseWriter, r *http.Request, v *visitor) error {
	req, err := readJSONWithLimit[apiUserAddOrUpdateRequest](r.Body, jsonBodyBytesLimit, false)
	if err != nil {
		return err
	} else if !user.AllowedUsername(req.Username) {
		return errHTTPBadRequest.Wrap("username invalid")
	} else if req.Password == "" && req.Hash == "" && req.Tier == "" {
		return errHTTPBadRequest.Wrap("need to provide at least one of \"password\", \"password_hash\" or \"tier\"")
	}
	u, err := s.userManager.User(req.Username)
	if err != nil && !errors.Is(err, user.ErrUserNotFound) {
		return err
	} else if u != nil {
		if u.IsAdmin() {
			return errHTTPForbidden
		}
		if req.Hash != "" {
			if err := s.userManager.ChangePassword(req.Username, req.Hash, true); err != nil {
				return err
			}
		} else if req.Password != "" {
			if err := s.userManager.ChangePassword(req.Username, req.Password, false); err != nil {
				return err
			}
		}
	} else {
		password, hashed := req.Password, false
		if req.Hash != "" {
			password, hashed = req.Hash, true
		}
		if err := s.userManager.AddUser(req.Username, password, user.RoleUser, hashed); err != nil {
			return err
		}
	}
	if req.Tier != "" {
		if _, err = s.userManager.Tier(req.Tier); errors.Is(err, user.ErrTierNotFound) {
			return errHTTPBadRequestTierInvalid
		} else if err != nil {
			return err
		}
		if err := s.userManager.ChangeTier(req.Username, req.Tier); err != nil {
			return err
		}
	}
	return s.writeJSON(w, newSuccessResponse())
}

func (s *Server) handleUsersDelete(w http.ResponseWriter, r *http.Request, v *visitor) error {
	req, err := readJSONWithLimit[apiUserDeleteRequest](r.Body, jsonBodyBytesLimit, false)
	if err != nil {
		return err
	}
	u, err := s.userManager.User(req.Username)
	if errors.Is(err, user.ErrUserNotFound) {
		return errHTTPBadRequestUserNotFound
	} else if err != nil {
		return err
	} else if !u.IsUser() {
		return errHTTPUnauthorized.Wrap("can only remove regular users from API")
	}
	if err := s.userManager.RemoveUser(req.Username); err != nil {
		return err
	}
	if err := s.killUserSubscriber(u, "*"); err != nil { // FIXME super inefficient
		return err
	}
	return s.writeJSON(w, newSuccessResponse())
}

// tokenToAdminResponse maps a token to the API response, blanking an unset last-origin the same way
// the self-service GET /v1/account handler does.
func tokenToAdminResponse(t *user.Token) *apiAccountTokenResponse {
	var lastOrigin string
	if t.LastOrigin != netip.IPv4Unspecified() {
		lastOrigin = t.LastOrigin.String()
	}
	return &apiAccountTokenResponse{
		Token:       t.Value,
		Label:       t.Label,
		LastAccess:  t.LastAccess.Unix(),
		LastOrigin:  lastOrigin,
		Expires:     t.Expires.Unix(),
		Provisioned: t.Provisioned,
	}
}

// handleUsersTokensGet lists a user's access tokens (admin-only). The username is passed as the
// "username" query parameter, since GET requests carry no body.
func (s *Server) handleUsersTokensGet(w http.ResponseWriter, r *http.Request, v *visitor) error {
	username := readParam(r, "X-Username", "Username")
	u, err := s.userManager.User(username)
	if errors.Is(err, user.ErrUserNotFound) {
		return errHTTPBadRequestUserNotFound
	} else if err != nil {
		return err
	}
	tokens, err := s.userManager.Tokens(u.ID)
	if err != nil {
		return err
	}
	response := make([]*apiAccountTokenResponse, 0, len(tokens))
	for _, t := range tokens {
		response = append(response, tokenToAdminResponse(t))
	}
	return s.writeJSON(w, response)
}

// handleUsersTokensCreate creates an access token for another user (admin-only) and returns it,
// including the token value, so an admin can provision a service/app publisher without knowing that
// user's password. An omitted or zero "expires" creates a never-expiring token.
func (s *Server) handleUsersTokensCreate(w http.ResponseWriter, r *http.Request, v *visitor) error {
	req, err := readJSONWithLimit[apiUserTokenCreateRequest](r.Body, jsonBodyBytesLimit, false)
	if err != nil {
		return err
	}
	u, err := s.userManager.User(req.Username)
	if errors.Is(err, user.ErrUserNotFound) {
		return errHTTPBadRequestUserNotFound
	} else if err != nil {
		return err
	}
	var label string
	if req.Label != nil {
		label = *req.Label
	}
	// Default to a never-expiring token (Unix 0): the WHERE clause treats expires=0 as "no expiry",
	// which is what an app/service publisher wants.
	expires := time.Unix(0, 0)
	if req.Expires != nil {
		expires = time.Unix(*req.Expires, 0)
	}
	token, err := s.userManager.CreateToken(u.ID, label, expires, netip.IPv4Unspecified(), false)
	if err != nil {
		return err
	}
	logvr(v, r).Tag(tagAccount).Field("target_user_name", u.Name).Debug("Admin created token for user %s", u.Name)
	return s.writeJSON(w, tokenToAdminResponse(token))
}

// handleUsersTokensDelete deletes one of a user's access tokens (admin-only).
func (s *Server) handleUsersTokensDelete(w http.ResponseWriter, r *http.Request, v *visitor) error {
	req, err := readJSONWithLimit[apiUserTokenDeleteRequest](r.Body, jsonBodyBytesLimit, false)
	if err != nil {
		return err
	} else if req.Token == "" {
		return errHTTPBadRequestNoTokenProvided
	}
	u, err := s.userManager.User(req.Username)
	if errors.Is(err, user.ErrUserNotFound) {
		return errHTTPBadRequestUserNotFound
	} else if err != nil {
		return err
	}
	if err := s.userManager.RemoveToken(u.ID, req.Token); err != nil {
		if errors.Is(err, user.ErrProvisionedTokenChange) {
			return errHTTPConflictProvisionedTokenChange
		}
		return err
	}
	logvr(v, r).Tag(tagAccount).Field("target_user_name", u.Name).Debug("Admin deleted token for user %s", u.Name)
	return s.writeJSON(w, newSuccessResponse())
}

func (s *Server) handleAccessAllow(w http.ResponseWriter, r *http.Request, v *visitor) error {
	req, err := readJSONWithLimit[apiAccessAllowRequest](r.Body, jsonBodyBytesLimit, false)
	if err != nil {
		return err
	}
	_, err = s.userManager.User(req.Username)
	if errors.Is(err, user.ErrUserNotFound) {
		return errHTTPBadRequestUserNotFound
	} else if err != nil {
		return err
	}
	permission, err := user.ParsePermission(req.Permission)
	if err != nil {
		return errHTTPBadRequestPermissionInvalid
	}
	if err := s.userManager.AllowAccess(req.Username, req.Topic, permission); err != nil {
		return err
	}
	return s.writeJSON(w, newSuccessResponse())
}

func (s *Server) handleAccessReset(w http.ResponseWriter, r *http.Request, v *visitor) error {
	req, err := readJSONWithLimit[apiAccessResetRequest](r.Body, jsonBodyBytesLimit, false)
	if err != nil {
		return err
	}
	u, err := s.userManager.User(req.Username)
	if err != nil {
		return err
	}
	if err := s.userManager.ResetAccess(req.Username, req.Topic); err != nil {
		return err
	}
	if err := s.killUserSubscriber(u, req.Topic); err != nil { // This may be a pattern
		return err
	}
	return s.writeJSON(w, newSuccessResponse())
}

func (s *Server) killUserSubscriber(u *user.User, topicPattern string) error {
	topics, err := s.topicsFromPattern(topicPattern)
	if err != nil {
		return err
	}
	for _, t := range topics {
		t.CancelSubscriberUser(u.ID)
	}
	return nil
}
