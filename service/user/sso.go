package user

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/cloudreve/Cloudreve/v4/application/dependency"
	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/user"
	"github.com/cloudreve/Cloudreve/v4/inventory"
	"github.com/cloudreve/Cloudreve/v4/pkg/serializer"
	"github.com/cloudreve/Cloudreve/v4/pkg/setting"
	"github.com/cloudreve/Cloudreve/v4/pkg/util"
	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
)

const (
	ssoStatePrefix  = "sso_state_"
	ssoTicketPrefix = "sso_ticket_"
	ssoStateTTL     = 300 // 5 minutes
	ssoTicketTTL    = 60  // 1 minute
)

// ---------------------------------------------------------------------------
// Feishu OAuth2 endpoints (verified against official docs 2025-07)
// ---------------------------------------------------------------------------
const (
	feishuAuthURL  = "https://accounts.feishu.cn/open-apis/authen/v1/authorize"
	feishuTokenURL = "https://open.feishu.cn/open-apis/authen/v2/oauth/token"
	feishuUserURL  = "https://open.feishu.cn/open-apis/authen/v1/user_info"
)

// feishuTokenResponse is the v3 token endpoint response.
type feishuTokenResponse struct {
	Code             int    `json:"code"`
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int    `json:"refresh_token_expires_in"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// feishuUserResponse is the user_info endpoint response.
type feishuUserResponse struct {
	Code int            `json:"code"`
	Msg  string         `json:"msg"`
	Data feishuUserData `json:"data"`
}

type feishuUserData struct {
	Name            string `json:"name"`
	EnName          string `json:"en_name"`
	AvatarURL       string `json:"avatar_url"`
	AvatarThumb     string `json:"avatar_thumb"`
	AvatarMiddle    string `json:"avatar_middle"`
	AvatarBig       string `json:"avatar_big"`
	OpenID          string `json:"open_id"`
	UnionID         string `json:"union_id"`
	Email           string `json:"email"`
	EnterpriseEmail string `json:"enterprise_email"`
	UserID          string `json:"user_id"`
	Mobile          string `json:"mobile"`
	TenantKey       string `json:"tenant_key"`
	EmployeeNo      string `json:"employee_no"`
}

// ssoState stores intermediate SSO login state.
type ssoState struct {
	Provider string `json:"provider"`
	Redirect string `json:"redirect"`
	CSRF     string `json:"csrf"`
}

// ---------------------------------------------------------------------------
// Step 1: Start SSO login — generate authorize URL and redirect
// ---------------------------------------------------------------------------

type (
	SSOStartParameterCtx struct{}
	SSOStartService      struct {
		Provider string `uri:"provider" binding:"required"`
		Redirect string `form:"redirect"`
	}
)

func (s *SSOStartService) Start(c *gin.Context) (string, error) {
	dep := dependency.FromContext(c)
	providers := dep.SettingProvider().SSOProviders(c)

	var prov *setting.SSOProvider
	for i := range providers {
		if providers[i].ID == s.Provider {
			prov = &providers[i]
			break
		}
	}
	if prov == nil {
		return "", serializer.NewError(serializer.CodeNotFound, "SSO provider not found", nil)
	}

	if prov.Type != "feishu" {
		return "", serializer.NewError(serializer.CodeParamErr, "unsupported SSO provider type", nil)
	}

	// Generate state with CSRF token
	csrfToken := uuid.Must(uuid.NewV4()).String()
	stateKey := uuid.Must(uuid.NewV4()).String()
	state := ssoState{
		Provider: s.Provider,
		Redirect: s.Redirect,
		CSRF:     csrfToken,
	}
	stateJSON, _ := json.Marshal(state)

	kv := dep.KV()
	if err := kv.Set(ssoStatePrefix+stateKey, string(stateJSON), ssoStateTTL); err != nil {
		return "", serializer.NewError(serializer.CodeInternalSetting, "Failed to store SSO state", err)
	}

	// Build Feishu authorize URL
	callbackURL := buildSSOCallbackURL(dep.SettingProvider().SiteURL(c), s.Provider)
	authParams := url.Values{}
	authParams.Set("client_id", prov.ClientID)
	authParams.Set("response_type", "code")
	authParams.Set("redirect_uri", callbackURL)
	authParams.Set("state", stateKey)

	// No scopes requested — we only need open_id/name/avatar (returned without scope)
	authURL := fmt.Sprintf("%s?%s", feishuAuthURL, authParams.Encode())

	return authURL, nil
}

// ---------------------------------------------------------------------------
// Step 2: Callback — exchange code, fetch user info, resolve/create user
// ---------------------------------------------------------------------------

type (
	SSOCallbackParameterCtx struct{}
	SSOCallbackService      struct {
		Provider string `uri:"provider" binding:"required"`
		Code     string `form:"code"`
		State    string `form:"state"`
		Error    string `form:"error"`
	}
)

// Handle processes the SSO callback. It returns the redirect URL for the frontend.
func (s *SSOCallbackService) Handle(c *gin.Context) (string, error) {
	dep := dependency.FromContext(c)
	l := dep.Logger()

	if s.Error != "" {
		return "", serializer.NewError(serializer.CodeParamErr,
			fmt.Sprintf("SSO authorization denied: %s", s.Error), nil)
	}

	if s.State == "" || s.Code == "" {
		return "", serializer.NewError(serializer.CodeParamErr,
			"Missing state or code in callback", nil)
	}

	// Validate state
	kv := dep.KV()
	stateRaw, ok := kv.Get(ssoStatePrefix + s.State)
	if !ok {
		return "", serializer.NewError(serializer.CodeParamErr,
			"SSO state expired or invalid", nil)
	}
	_ = kv.Delete(ssoStatePrefix, s.State)

	var state ssoState
	if err := json.Unmarshal([]byte(stateRaw.(string)), &state); err != nil {
		return "", serializer.NewError(serializer.CodeParamErr,
			"SSO state corrupted", err)
	}

	if state.Provider != s.Provider {
		return "", serializer.NewError(serializer.CodeParamErr,
			"SSO provider mismatch", nil)
	}
	l.Info("SSO callback state validated: provider=%q", s.Provider)

	providers := dep.SettingProvider().SSOProviders(c)
	prov := findProvider(providers, s.Provider)
	if prov == nil {
		return "", serializer.NewError(serializer.CodeNotFound, "SSO provider not found", nil)
	}

	// Exchange code for token
	callbackURL := buildSSOCallbackURL(dep.SettingProvider().SiteURL(c), s.Provider)
	l.Info("SSO token exchange started: provider=%q", s.Provider)
	tokenResp, err := exchangeFeishuToken(prov.ClientID, prov.ClientSecret, s.Code, callbackURL)
	if err != nil {
		l.Warning("SSO token exchange failed: provider=%q error=%s", s.Provider, err)
		return "", err
	}
	l.Info("SSO token exchange completed: provider=%q", s.Provider)

	// Fetch user info
	l.Info("SSO user info lookup started: provider=%q", s.Provider)
	userInfo, err := fetchFeishuUser(tokenResp.AccessToken)
	if err != nil {
		l.Warning("SSO user info lookup failed: provider=%q error=%s", s.Provider, err)
		return "", err
	}

	if userInfo.Data.OpenID == "" {
		return "", serializer.NewError(serializer.CodeInternalSetting,
			"Feishu returned empty open_id", nil)
	}
	l.Info("SSO user info lookup completed: provider=%q", s.Provider)

	// Resolve or create user
	fedClient := dep.FederatedIdentityClient()
	userClient := dep.UserClient()

	ctx := context.WithValue(c, inventory.LoadUserGroup{}, true)
	existingBind, err := fedClient.GetByProviderSubject(ctx, s.Provider, userInfo.Data.OpenID)
	if err == nil && existingBind != nil && existingBind.Edges.User != nil {
		// Existing binding — update last_used_at
		if err := fedClient.MarkUsed(ctx, existingBind.ID); err != nil {
			l.Warning("SSO binding last-used update failed: provider=%q binding_id=%d error=%s", s.Provider, existingBind.ID, err)
		}
		l.Info("SSO existing binding resolved: provider=%q user_id=%d", s.Provider, existingBind.Edges.User.ID)

		// Set user into context for token issuance
		util.WithValue(c, inventory.UserCtx{}, existingBind.Edges.User)

		// Build redirect URL with ticket
		return buildSSORedirect(c, dep, state.Redirect, existingBind.Edges.User)
	}
	if !ent.IsNotFound(err) {
		l.Error("SSO binding lookup failed: provider=%q error=%s", s.Provider, err)
		return "", serializer.NewError(serializer.CodeDBError, "Failed to resolve SSO identity", err)
	}
	if !prov.AllowSignup {
		l.Warning("SSO signup denied for unbound identity: provider=%q", s.Provider)
		return "", serializer.NewError(serializer.CodeNoPermissionErr, "SSO signup is disabled", nil)
	}

	// No existing binding — create a new user and its binding atomically.
	// Use open_id as synthetic email; Feishu name as nick
	email := fmt.Sprintf("%s@feishu.sso.local", userInfo.Data.OpenID)
	nick := userInfo.Data.Name
	if nick == "" {
		nick = userInfo.Data.EnName
	}
	if nick == "" {
		nick = fmt.Sprintf("Feishu %s", userInfo.Data.OpenID[:8])
	}

	avatar := userInfo.Data.AvatarBig
	if avatar == "" {
		avatar = userInfo.Data.AvatarURL
	}

	txUserClient, tx, txCtx, err := inventory.WithTx(ctx, userClient)
	if err != nil {
		l.Error("SSO transaction start failed: provider=%q error=%s", s.Provider, err)
		return "", serializer.NewError(serializer.CodeDBError, "Failed to start SSO signup transaction", err)
	}
	txFedClient, _, txCtx, err := inventory.WithTx(txCtx, fedClient)
	if err != nil {
		_ = inventory.Rollback(tx)
		l.Error("SSO binding transaction setup failed: provider=%q error=%s", s.Provider, err)
		return "", serializer.NewError(serializer.CodeDBError, "Failed to start SSO signup transaction", err)
	}

	newUser, err := txUserClient.Create(txCtx, &inventory.NewUserArgs{
		Email:         email,
		Nick:          nick,
		PlainPassword: "", // SSO-only user, no password
		Status:        user.StatusActive,
		GroupID:       dep.SettingProvider().DefaultGroup(c),
		Avatar:        avatar,
	})
	if err != nil {
		_ = inventory.Rollback(tx)
		l.Warning("SSO user creation failed: provider=%q error=%s", s.Provider, err)
		return "", serializer.NewError(serializer.CodeDBError,
			"Failed to create SSO user", err)
	}

	// Create federated identity binding
	_, err = txFedClient.Create(txCtx, newUser.ID, s.Provider, userInfo.Data.OpenID, userInfo.Data.UnionID)
	if err != nil {
		_ = inventory.Rollback(tx)
		l.Error("SSO binding creation failed: provider=%q user_id=%d error=%s", s.Provider, newUser.ID, err)
		return "", serializer.NewError(serializer.CodeDBError,
			"Failed to create SSO binding", err)
	}
	if err := inventory.Commit(tx); err != nil {
		l.Error("SSO signup transaction commit failed: provider=%q user_id=%d error=%s", s.Provider, newUser.ID, err)
		return "", serializer.NewError(serializer.CodeDBError, "Failed to save SSO identity", err)
	}
	l.Info("SSO user and binding created: provider=%q user_id=%d", s.Provider, newUser.ID)

	util.WithValue(c, inventory.UserCtx{}, newUser)

	return buildSSORedirect(c, dep, state.Redirect, newUser)
}

// buildSSORedirect issues a JWT token pair, stores it in KV as a ticket,
// and returns the frontend redirect URL.
func buildSSORedirect(c *gin.Context, dep dependency.Dep, originalRedirect string, u *ent.User) (string, error) {
	// Issue standard JWT token pair
	resp, err := IssueToken(c)
	if err != nil {
		return "", err
	}

	// Serialize and store in KV
	ticket := uuid.Must(uuid.NewV4()).String()
	ticketData, err := json.Marshal(resp)
	if err != nil {
		return "", serializer.NewError(serializer.CodeInternalSetting,
			"Failed to serialize login response", err)
	}
	if err := dep.KV().Set(ssoTicketPrefix+ticket, string(ticketData), ssoTicketTTL); err != nil {
		dep.Logger().Error("SSO ticket storage failed: user_id=%d error=%s", u.ID, err)
		return "", serializer.NewError(serializer.CodeInternalSetting,
			"Failed to store SSO ticket", err)
	}
	dep.Logger().Info("SSO login ticket issued: user_id=%d", u.ID)

	// Build redirect URL
	frontendBase := dep.SettingProvider().SiteURL(c)
	frontendBase.Path = "/callback/sso"
	q := frontendBase.Query()
	q.Set("ticket", ticket)
	if originalRedirect != "" {
		q.Set("redirect", originalRedirect)
	}
	frontendBase.RawQuery = q.Encode()

	return frontendBase.String(), nil
}

// ---------------------------------------------------------------------------
// Step 3: Finish — exchange ticket for LoginResponse
// ---------------------------------------------------------------------------

type (
	SSOFinishParameterCtx struct{}
	SSOFinishService      struct {
		Ticket string `json:"ticket" binding:"required"`
	}
)

func (s *SSOFinishService) Finish(c *gin.Context) (*BuiltinLoginResponse, error) {
	dep := dependency.FromContext(c)
	kv := dep.KV()

	raw, ok := kv.Get(ssoTicketPrefix + s.Ticket)
	if !ok {
		dep.Logger().Warning("SSO ticket exchange failed: ticket not found")
		return nil, serializer.NewError(serializer.CodeNotFound,
			"SSO ticket expired or invalid", nil)
	}
	_ = kv.Delete(ssoTicketPrefix, s.Ticket)

	var resp BuiltinLoginResponse
	if err := json.Unmarshal([]byte(raw.(string)), &resp); err != nil {
		dep.Logger().Error("SSO ticket exchange failed: malformed ticket payload error=%s", err)
		return nil, serializer.NewError(serializer.CodeInternalSetting,
			"SSO ticket corrupted", err)
	}
	dep.Logger().Info("SSO ticket exchange completed: user_id=%s", resp.User.ID)

	return &resp, nil
}

// ---------------------------------------------------------------------------
// Feishu API helpers
// ---------------------------------------------------------------------------

func exchangeFeishuToken(clientID, clientSecret, code, redirectURI string) (*feishuTokenResponse, error) {
	body := map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     clientID,
		"client_secret": clientSecret,
		"code":          code,
		"redirect_uri":  redirectURI,
	}
	bodyJSON, _ := json.Marshal(body)

	resp, err := http.Post(feishuTokenURL, "application/json; charset=utf-8",
		bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, serializer.NewError(serializer.CodeInternalSetting,
			"Failed to contact Feishu token endpoint", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeInternalSetting,
			"Failed to read Feishu token response", err)
	}

	var tokenResp feishuTokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, serializer.NewError(serializer.CodeInternalSetting,
			"Failed to parse Feishu token response", err)
	}

	if tokenResp.Code != 0 {
		return nil, serializer.NewError(serializer.CodeParamErr,
			fmt.Sprintf("Feishu token error %d: %s", tokenResp.Code, tokenResp.ErrorDescription), nil)
	}

	return &tokenResp, nil
}

func fetchFeishuUser(accessToken string) (*feishuUserResponse, error) {
	req, err := http.NewRequest("GET", feishuUserURL, nil)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeInternalSetting,
			"Failed to build Feishu user info request", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeInternalSetting,
			"Failed to contact Feishu user info endpoint", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, serializer.NewError(serializer.CodeInternalSetting,
			"Failed to read Feishu user info response", err)
	}

	var userResp feishuUserResponse
	if err := json.Unmarshal(respBody, &userResp); err != nil {
		return nil, serializer.NewError(serializer.CodeInternalSetting,
			"Failed to parse Feishu user info response", err)
	}

	if userResp.Code != 0 {
		return nil, serializer.NewError(serializer.CodeParamErr,
			fmt.Sprintf("Feishu user info error %d: %s", userResp.Code, userResp.Msg), nil)
	}

	return &userResp, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func findProvider(providers []setting.SSOProvider, id string) *setting.SSOProvider {
	for i := range providers {
		if providers[i].ID == id {
			return &providers[i]
		}
	}
	return nil
}

func buildSSOCallbackURL(siteURL *url.URL, providerID string) string {
	u := *siteURL
	u.Path = fmt.Sprintf("/api/v4/session/sso/%s/callback", providerID)
	u.RawQuery = ""
	return u.String()
}
