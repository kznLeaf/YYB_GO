package protocol

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"
)

const (
	// yybHost 腾讯应用宝鉴权服务的基础域名。
	yybHost = "https://yybadaccess.3g.qq.com"
	// loginBufferURL 获取 LoginBuffer 的接口地址。
	loginBufferURL = yybHost + "/pc_yyb_auth/pcyyb_get_wx_login_buffer_auth"
	// refreshTokenURL 刷新登录凭证 (Token) 的接口地址。
	refreshTokenURL = yybHost + "/pc_yyb_auth/pcyyb_refresh_token_auth"
	// userInfoURL 获取用户详细信息的接口地址。
	userInfoURL = yybHost + "/pc_yyb/pcyyb_get_user_info"
	// loginBusinessID 鉴权请求中使用的固定业务 ID。
	loginBusinessID = "pc_yyb_auth"
	// loginAccessKey 用于生成请求签名的固定 Access Key。
	loginAccessKey = "wgrdg373hy26ww2"
)

// LoginBufferCredentials 存储从 Cookie 提取的信息
type LoginBufferCredentials struct {
	OpenID       string `json:"openid"`
	AccessToken  string `json:"accesstoken"`
	RefreshToken string `json:"refreshtoken"`
	LoginType    string `json:"logintype"`
	Nickname     string `json:"nickname"`
	ExpiresAt    int64  `json:"expires_at"`
	ExpiresIn    int64  `json:"expires_in"`
}

// CredentialsFromMap 从 map[string]any 中提取字段并构造 LoginBufferCredentials 对象。
func CredentialsFromMap(m map[string]any) LoginBufferCredentials {
	return LoginBufferCredentials{
		OpenID:       stringFromMap(m, "openid"),
		AccessToken:  stringFromMap(m, "accesstoken"),
		RefreshToken: stringFromMap(m, "refreshtoken"),
		LoginType:    defaultString(stringFromMap(m, "logintype"), "WX"),
		Nickname:     stringFromMap(m, "nickname"),
		ExpiresAt:    int64FromMap(m, "expires_at"),
		ExpiresIn:    defaultInt64(int64FromMap(m, "expires_in"), 7200),
	}
}

// ToMap 将 LoginBufferCredentials 转换为 map[string]any，
// 并附加当前的刷新时间戳，便于序列化或持久化存储。
func (c LoginBufferCredentials) ToMap() map[string]any {
	return map[string]any{
		"openid":               c.OpenID,
		"accesstoken":          c.AccessToken,
		"refreshtoken":         c.RefreshToken,
		"logintype":            defaultString(c.LoginType, "WX"),
		"nickname":             c.Nickname,
		"expires_at":           c.ExpiresAt,
		"expires_in":           defaultInt64(c.ExpiresIn, 7200),
		"refresh_refreshed_at": time.Now().Unix(),
	}
}

// Expired 判断当前凭证是否已过期。
// skew 参数允许传入一个时间偏移量，用于提前判定即将过期的凭证。
func (c LoginBufferCredentials) Expired(skew time.Duration) bool {
	return time.Now().Add(skew).Unix() >= c.ExpiresAt
}

// LoginBufferResult 封装获取 LoginBuffer 的结果，包含 Buffer 字符串、更新后的凭证及是否刚执行了刷新操作。
type LoginBufferResult struct {
	LoginBuffer string
	Credentials LoginBufferCredentials
	Refreshed   bool
}

// LoginBufferClient 封装了与应用宝鉴权服务进行 HTTP 交互的客户端。
type LoginBufferClient struct {
	httpClient *http.Client
	timeout    time.Duration
}

// NewLoginBufferClient 创建并初始化一个新的 LoginBufferClient 实例。
func NewLoginBufferClient(timeout time.Duration) *LoginBufferClient {
	return &LoginBufferClient{
		httpClient: &http.Client{Timeout: timeout},
		timeout:    timeout,
	}
}

// FetchLoginBuffer 使用提供的凭证向服务器请求获取最新的 LoginBuffer。
// 它会构造特定的 JSON 请求体，并附带必要的鉴权 Header（如 Timestamp, Nonce, Signature）和 Cookie。
func (c *LoginBufferClient) FetchLoginBuffer(ctx context.Context, creds LoginBufferCredentials) (string, error) {
	// 使用 Cookies 中的信息填充请求体
	body, err := json.Marshal(loginBufferRequest{
		ExtInfo: loginExtInfo{
			ListS: loginListS{
				UnionID:     loginValueString{Value: []string{creds.OpenID}},
				UserID:      loginValueString{Value: []string{creds.OpenID}},
				AccessToken: loginValueString{Value: []string{creds.AccessToken}},
			},
			ListI: loginListI{UserType: loginValueInt{Value: []int{0}}},
		},
	})
	if err != nil {
		return "", err
	}

	ts, nonce := timestampMS(), nonce4()

	var data map[string]any
	if err = c.requestJSON(ctx, http.MethodPost, loginBufferURL, body, map[string]string{
		"Content-Type":          "application/json",
		"Ual-Access-Businessid": loginBusinessID,
		"Ual-Access-Timestamp":  ts,
		"Ual-Access-Nonce":      nonce,
		"Ual-Access-Signature":  sign(string(body), nonce, ts, loginAccessKey),
		"Cookie":                fmt.Sprintf("openid=%s; accesstoken=%s; refreshtoken=%s", creds.OpenID, creds.AccessToken, creds.RefreshToken),
	}, &data); err != nil {
		return "", err
	}

	if intFromAny(data["code"]) != 0 {
		return "", fmt.Errorf("login_buffer failed: code=%v msg=%v", data["code"], data["msg"])
	}
	values := stringSlicePath(data, "ext_info", "list_s", "login_buffer", "value")
	if len(values) == 0 || values[0] == "" {
		return "", fmt.Errorf("login_buffer response is empty")
	}
	return values[0], nil
}

// RefreshCredentials 使用 RefreshToken 向服务器请求刷新 AccessToken 和其他相关凭证信息。
func (c *LoginBufferClient) RefreshCredentials(ctx context.Context, creds LoginBufferCredentials) (LoginBufferCredentials, error) {
	if creds.RefreshToken == "" {
		return LoginBufferCredentials{}, fmt.Errorf("missing refresh token")
	}
	body, err := json.Marshal(refreshTokenRequest{UserInfo: refreshTokenUserInfo{
		OpenID:       creds.OpenID,
		RefreshToken: creds.RefreshToken,
		AccessToken:  creds.AccessToken,
		LoginType:    defaultString(creds.LoginType, "WX"),
	}})
	if err != nil {
		return LoginBufferCredentials{}, err
	}
	ts, nonce := timestampMS(), nonce4()
	var data map[string]any
	if err = c.requestJSON(ctx, http.MethodPost, refreshTokenURL, body, map[string]string{
		"Content-Type":          "application/json",
		"Ual-Access-Businessid": loginBusinessID,
		"Ual-Access-Timestamp":  ts,
		"Ual-Access-Nonce":      nonce,
		"Ual-Access-Signature":  sign(string(body), nonce, ts, loginAccessKey),
	}, &data); err != nil {
		return LoginBufferCredentials{}, err
	}
	if intFromAny(data["code"]) != 0 {
		return LoginBufferCredentials{}, fmt.Errorf("refresh failed: code=%v msg=%v", data["code"], data["msg"])
	}
	info, _ := data["user_info"].(map[string]any)
	expiresIn := defaultInt64(int64FromMap(info, "expires_in"), 7200)
	refreshed := creds
	refreshed.AccessToken = stringFromMap(info, "access_token")
	if rt := stringFromMap(info, "refresh_token"); rt != "" {
		refreshed.RefreshToken = rt
	}
	refreshed.ExpiresIn = expiresIn
	refreshed.ExpiresAt = time.Now().Unix() + expiresIn
	if refreshed.AccessToken == "" {
		return LoginBufferCredentials{}, fmt.Errorf("refresh response missing access_token")
	}
	return refreshed, nil
}

// RefreshLoginBuffer 执行组合操作：先调用 RefreshCredentials 刷新凭证，
// 然后使用更新后的凭证调用 FetchLoginBuffer 获取新的 LoginBuffer。
func (c *LoginBufferClient) RefreshLoginBuffer(ctx context.Context, creds LoginBufferCredentials) (LoginBufferResult, error) {
	refreshed, err := c.RefreshCredentials(ctx, creds)
	if err != nil {
		return LoginBufferResult{}, err
	}
	lb, err := c.FetchLoginBuffer(ctx, refreshed)
	if err != nil {
		return LoginBufferResult{}, err
	}
	return LoginBufferResult{LoginBuffer: lb, Credentials: refreshed, Refreshed: true}, nil
}

// FetchUserInfo 使用当前凭证向服务器请求获取用户的详细信息。
func (c *LoginBufferClient) FetchUserInfo(ctx context.Context, creds LoginBufferCredentials) (map[string]any, error) {
	ts, nonce := timestampMS(), nonce4()
	var data map[string]any
	err := c.requestJSON(ctx, http.MethodGet, userInfoURL, nil, map[string]string{
		"Ual-Access-Access-Token": creds.AccessToken,
		"Ual-Access-Login-Type":   "2",
		"Ual-Access-Openid":       creds.OpenID,
		"Ual-Access-Businessid":   "pc_yyb",
		"Ual-Access-Guid":         "web",
		"Ual-Access-Nonce":        nonce,
		"Ual-Access-Requestid":    fmt.Sprintf("%d", rand.Intn(9000)+1000),
		"Ual-Access-Signature":    sign("", nonce, ts, ""),
		"Ual-Access-Timestamp":    ts,
	}, &data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// requestJSON 核心 HTTP 请求封装方法。
// 负责构建请求、设置 Header、发送请求、检查 HTTP 状态码，并将响应体解析为 JSON 到 out 参数中。
func (c *LoginBufferClient) requestJSON(ctx context.Context, method, url string, body []byte, headers map[string]string, out any) error {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(data[:min(len(data), 200)]))
	}
	if err = json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode JSON: %w: %s", err, string(data[:min(len(data), 200)]))
	}
	return nil
}

// 以下结构体为内部使用的 JSON 序列化辅助结构

type loginBufferRequest struct {
	ExtInfo loginExtInfo `json:"extInfo"`
}
type loginExtInfo struct {
	ListS loginListS `json:"listS"`
	ListI loginListI `json:"listI"`
}
type loginListS struct {
	UnionID     loginValueString `json:"unionid"`
	UserID      loginValueString `json:"user_id"`
	AccessToken loginValueString `json:"access_token"`
}
type loginListI struct {
	UserType loginValueInt `json:"user_type"`
}
type loginValueString struct {
	Value []string `json:"value"`
}
type loginValueInt struct {
	Value []int `json:"value"`
}
type refreshTokenRequest struct {
	UserInfo refreshTokenUserInfo `json:"userInfo"`
}
type refreshTokenUserInfo struct {
	OpenID       string `json:"openId"`
	RefreshToken string `json:"refreshToken"`
	AccessToken  string `json:"accessToken"`
	LoginType    string `json:"loginType"`
}

// timestampMS 生成当前时间的毫秒级时间戳字符串。
func timestampMS() string {
	return fmt.Sprintf("%d", time.Now().UnixMilli())
}

// nonce4 生成一个 4 位的随机数字字符串，用作请求的防重放 Nonce。
func nonce4() string {
	return fmt.Sprintf("%d", rand.Intn(10000))
}

// sign 根据请求体、时间戳、Nonce 和 Access Key 生成 MD5 签名，用于接口鉴权。
func sign(body, nonce, ts, key string) string {
	sum := md5.Sum([]byte(body + ts + key + nonce))
	return hex.EncodeToString(sum[:])
}

// stringSlicePath 在嵌套的 map[string]any 中，按照给定的路径 (path) 安全地提取字符串切片。
// 若路径中任意一环类型不匹配或不存在，则返回 nil。
func stringSlicePath(m map[string]any, path ...string) []string {
	var cur any = m
	for _, p := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = obj[p]
	}
	arr, ok := cur.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// stringFromMap 从 map 中安全地提取指定 key 的字符串值。
// 若 map 为 nil、key 不存在或类型不匹配，则返回空字符串。
func stringFromMap(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

// int64FromMap 从 map 中安全地提取指定 key 的 int64 值。
// 支持 int, int64, float64 和 json.Number 类型的自动转换。
func int64FromMap(m map[string]any, key string) int64 {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case float64:
		return int64(v)
	case json.Number:
		n, _ := v.Int64()
		return n
	default:
		return 0
	}
}

// intFromAny 将任意类型的值安全地转换为 int。
// 支持 int, int64, float64 和 json.Number 类型。
func intFromAny(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case json.Number:
		n, _ := x.Int64()
		return int(n)
	default:
		return 0
	}
}

// defaultString 辅助函数：若输入字符串 s 为空，则返回默认值 def；否则返回 s。
func defaultString(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// defaultInt64 辅助函数：若输入 int64 值 v 为 0，则返回默认值 def；否则返回 v。
func defaultInt64(v, def int64) int64 {
	if v == 0 {
		return def
	}
	return v
}
