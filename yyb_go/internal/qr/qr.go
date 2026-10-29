package qr

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"time"

	"yyb_go/internal/protocol"
)

const (
	oauthURL = "https://open.weixin.qq.com/connect/qrconnect" +
		"?appid=wxd44977328b36e647" +
		"&redirect_uri=https://yybadaccess.3g.qq.com/pc_yyb/pcyyb_oauth?login_type=WX" +
		"&response_type=code&scope=snsapi_login,snsapi_runtime_pcsdk" +
		"&state=web&fast_login=1&self_redirect=true"
	// 应用宝的认证和鉴权URL
	//
	// - 触发回调：当用户在手机上微信扫码并点击“确认登录”后，微信长轮询会返回一个临时的 AuthorizeCode
	//
	// - 请求兑换：代码中的 GetLoginBuffer 方法会构造一个请求，携带code访问
	// https://yybadaccess.3g.qq.com/pc_yyb/pcyyb_oauth?login_type=WX&code=...
	//
	// - 下发凭证 (Cookie)：这个接口在验证 code 有效后，会在 HTTP 响应中通过 Set-Cookie
	// 头部下发一系列关键的身份凭证，包括 openid、accesstoken、refreshtoken 和 nickname 等。
	//
	// - 提取并构建会话：credentialsFromJar 函数会从 cookie 中精准提取这些 Cookie，
	// 并将其组装成 protocol.LoginBufferCredentials 结构体。
	//
	// - 获取最终登录态：最后，代码使用这些凭证去调用底层的 FetchLoginBuffer，换取最终的 LoginBuffer
	// （这通常是腾讯 PC 客户端内部协议用于维持长连接登录态的核心 Token）。
	callbackURL  = "https://yybadaccess.3g.qq.com/pc_yyb/pcyyb_oauth"
	qrBase       = "https://open.weixin.qq.com/connect/qrcode/"
	longPollBase = "https://long.open.weixin.qq.com/connect/l/qrconnect"
)

var (
	// uuidRE 获取二维码的UUID
	// e.g. <img src="/connect/qrcode/041a2b3c4d5e6f7g" />
	// -> 041a2b3c4d5e6f7g
	uuidRE = regexp.MustCompile(`/connect/qrcode/([^"'>\s]+)`)
	// errRE match status code.
	// e.g. window.wx_errcode = 405; -> 405
	errRE = regexp.MustCompile(`wx_errcode\s*=\s*(\d+)`)
	// codeRE 提取登录返回的code.
	// window.wx_code='XXX';
	codeRE = regexp.MustCompile(`wx_code\s*=\s*'([^']*)'`)
)

type Session struct {
	ID     string
	WXUUID string
	// QRCodeURL is fixed to qrBase + wxuuid
	//
	// i.e. "https://open.weixin.qq.com/connect/qrcode/{wxuuid}"
	QRCodeURL  string
	CreatedAt  time.Time
	HTTPClient *http.Client
	// Jar 是 Cookie 的实现。应用宝的登录接口在成功登录后通过 Cookie
	// 返回 token 等信息，所以需要这个字段
	Jar           http.CookieJar
	AuthorizeCode string
	Credentials   *protocol.LoginBufferCredentials
	LoginBuffer   string
	Status        string
	Error         string
	mu            sync.Mutex
}

// Age 返回 Session 创建至今经过的时间。
func (s *Session) Age() time.Duration { return time.Since(s.CreatedAt) }

type ImageResult struct {
	Session    *Session
	ImageBytes []byte
}

type PollResult struct {
	Status  string `json:"status"`
	ErrCode *int   `json:"errcode,omitempty"`
	Code    string `json:"-"`
	Message string `json:"-"`
}

type Client struct {
	timeout      time.Duration
	loginBuffers *protocol.LoginBufferClient
}

// NewClient 创建并返回一个新的 Client 实例，用于处理微信扫码登录流程，
// 同时初始化底层的 LoginBufferClient。
func NewClient(timeout time.Duration) *Client {
	return &Client{
		timeout:      timeout,
		loginBuffers: protocol.NewLoginBufferClient(timeout),
	}
}

// LoginBuffers 返回客户端内部使用的 LoginBufferClient 实例，
// 供外部需要直接操作底层登录缓冲协议时调用。
func (c *Client) LoginBuffers() *protocol.LoginBufferClient { return c.loginBuffers }

// GetQRCodeImage 创建一个新的登录会话，并获取对应的二维码图片原始字节数据。
// 这是一个组合方法，封装了 CreateSession 和 FetchQRCodeImage 的调用。
func (c *Client) GetQRCodeImage(ctx context.Context) (ImageResult, error) {
	sess, err := c.CreateSession(ctx)
	if err != nil {
		return ImageResult{}, err
	}
	data, err := c.FetchQRCodeImage(ctx, sess)
	if err != nil {
		return ImageResult{}, err
	}
	return ImageResult{Session: sess, ImageBytes: data}, nil
}

// CreateSession 创建一个新的登录会话。它会向微信服务器发起请求以获取二维码的唯一 UUID，
// 并配置带有独立 CookieJar 的 HTTP 客户端，以维持该会话的后续状态和请求。
func (c *Client) CreateSession(ctx context.Context) (*Session, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	hc := &http.Client{Timeout: c.timeout, Jar: jar}
	// 访问应用宝的认证和鉴权URL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, oauthURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	m := uuidRE.FindStringSubmatch(string(body))
	if len(m) < 2 {
		return nil, fmt.Errorf("failed to parse WeChat QR uuid")
	}
	id, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	// qrcode uuid
	wxuuid := m[1]
	log.Printf("QRcode UUID(wxuuid): %s\n", wxuuid)
	return &Session{
		ID:         id,
		WXUUID:     wxuuid,
		QRCodeURL:  qrBase + wxuuid,
		CreatedAt:  time.Now(),
		HTTPClient: hc,
		Jar:        jar,
		Status:     "pending",
	}, nil
}

// FetchQRCodeImage 根据会话中存储的二维码 URL，向微信服务器请求并下载二维码图片的原始字节数据。
func (c *Client) FetchQRCodeImage(ctx context.Context, sess *Session) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sess.QRCodeURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := sess.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("QR image HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// PollQRCode 通过长轮询机制检查当前会话的扫码状态（用户完成扫码动作需要时间）
// 解析微信服务器返回的响应文本，提取状态码和授权码，并据此更新会话的内部状态
// (如 pending, scanned, authorized, cancelled, expired 等)。
func (c *Client) PollQRCode(ctx context.Context, sess *Session) (PollResult, error) {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.LoginBuffer != "" {
		return PollResult{Status: "confirmed"}, nil
	}
	if sess.AuthorizeCode != "" {
		code := 405
		return PollResult{Status: "authorized", ErrCode: &code, Code: sess.AuthorizeCode}, nil
	}

	u := longPollBase + "?" + url.Values{
		"uuid": {sess.WXUUID},
		"_":    {strconv.FormatInt(time.Now().UnixMilli(), 10)},
	}.Encode()

	reqCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, u, nil)
	if err != nil {
		return PollResult{}, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := sess.HTTPClient.Do(req)
	if err != nil {
		return PollResult{}, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	text := string(body)

	errcode, code := parsePoll(text)
	switch {
	case errcode != nil && *errcode == 408:
		sess.Status = "pending"
		return PollResult{Status: "pending", ErrCode: errcode, Code: code}, nil
	case errcode != nil && *errcode == 404:
		sess.Status = "scanned"
		return PollResult{Status: "scanned", ErrCode: errcode, Code: code}, nil
	case errcode != nil && *errcode == 403:
		sess.Status = "cancelled"
		return PollResult{Status: "cancelled", ErrCode: errcode, Code: code}, nil
	case errcode != nil && *errcode == 402:
		sess.Status = "expired"
		return PollResult{Status: "expired", ErrCode: errcode, Code: code}, nil
	case errcode != nil && *errcode == 405 && code != "":
		// 405 Method Not Allowed
		sess.AuthorizeCode = code
		log.Printf("AuthorizeCode: %s\n", code)
		sess.Status = "authorized"
		return PollResult{Status: "authorized", ErrCode: errcode, Code: code}, nil
	default:
		sess.Status = "unknown"
		if len(text) > 200 {
			text = text[:200]
		}
		sess.Error = text
		return PollResult{Status: "unknown", ErrCode: errcode, Code: code, Message: text}, nil
	}
}

// GetLoginBuffer 在会话已授权后，通过模拟回调 URL 触发登录流程。
// 它会从会话的 CookieJar 中提取必要的凭证信息（如 OpenID、AccessToken），
// 并向底层协议客户端请求获取最终的 LoginBuffer，完成登录态的建立。
func (c *Client) GetLoginBuffer(ctx context.Context, sess *Session) (protocol.LoginBufferResult, error) {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.LoginBuffer != "" && sess.Credentials != nil {
		return protocol.LoginBufferResult{LoginBuffer: sess.LoginBuffer, Credentials: *sess.Credentials}, nil
	}
	if sess.AuthorizeCode == "" {
		return protocol.LoginBufferResult{}, fmt.Errorf("QR session is not authorized yet")
	}

	// 携带 code 访问回调URL, 以便获取Cookies
	// cb 是拼接后的URL
	cb := callbackURL + "?" + url.Values{
		"login_type": {"WX"},
		"code":       {sess.AuthorizeCode},
		"state":      {"web"},
	}.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cb, nil)
	if err != nil {
		return protocol.LoginBufferResult{}, err
	}

	// 请求cb
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := sess.HTTPClient.Do(req)
	if err != nil {
		return protocol.LoginBufferResult{}, err
	}

	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	// 现在session已经有了cookies
	creds, err := credentialsFromJar(sess.Jar, cb)
	if err != nil {
		return protocol.LoginBufferResult{}, err
	}

	lb, err := c.loginBuffers.FetchLoginBuffer(ctx, creds)
	if err != nil {
		return protocol.LoginBufferResult{}, err
	}

	sess.Credentials = &creds
	sess.LoginBuffer = lb
	sess.Status = "confirmed"

	return protocol.LoginBufferResult{LoginBuffer: lb, Credentials: creds}, nil
}

// RefreshLoginBuffer 使用已有的登录凭证刷新 LoginBuffer，以延长登录态的有效期。
func (c *Client) RefreshLoginBuffer(ctx context.Context, creds protocol.LoginBufferCredentials) (protocol.LoginBufferResult, error) {
	return c.loginBuffers.RefreshLoginBuffer(ctx, creds)
}

// DataURIJPEG 将 JPEG 图片的字节数据转换为 Base64 编码的 Data URI 字符串，
// 便于在前端 HTML 或 JSON 响应中直接渲染图片。
func DataURIJPEG(data []byte) string {
	return "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(data)
}

// parsePoll 解析微信长轮询返回的 JavaScript 文本响应，
// 用正则提取其中的错误码 (wx_errcode) 和授权码 (wx_code)。
func parsePoll(text string) (*int, string) {
	var out *int
	if m := errRE.FindStringSubmatch(text); len(m) == 2 {
		n, _ := strconv.Atoi(m[1])
		out = &n
	}
	code := ""
	if m := codeRE.FindStringSubmatch(text); len(m) == 2 {
		code = m[1]
	}
	return out, code
}

// credentialsFromJar 从 HTTP CookieJar 中提取微信扫码登录回调后设置的关键凭证信息，
// 包括 OpenID、AccessToken、RefreshToken 等，并构造为 protocol.LoginBufferCredentials 结构体。
func credentialsFromJar(jar http.CookieJar, rawURL string) (protocol.LoginBufferCredentials, error) {
	u, _ := url.Parse(rawURL)
	var cookies []*http.Cookie
	if u != nil {
		cookies = append(cookies, jar.Cookies(u)...)
	}

	hostURL, _ := url.Parse("https://yybadaccess.3g.qq.com/")
	cookies = append(cookies, jar.Cookies(hostURL)...)

	// 将所有 cookie 保存到map
	values := map[string]string{}
	for _, ck := range cookies {
		values[ck.Name] = ck.Value
	}

	openid := values["openid"]
	accessToken := values["accesstoken"]
	if openid == "" || accessToken == "" {
		return protocol.LoginBufferCredentials{}, fmt.Errorf("OAuth callback did not set required cookies")
	}

	// 读取 cookie 的过期时间，如果没有就设为默认值7200
	expiresIn := int64(7200)
	if values["expires_in"] != "" {
		if n, err := strconv.ParseInt(values["expires_in"], 10, 64); err == nil && n > 0 {
			expiresIn = n
		}
	}

	return protocol.LoginBufferCredentials{
		OpenID:       openid,
		AccessToken:  accessToken,
		RefreshToken: values["refreshtoken"],
		LoginType:    defaultString(values["logintype"], "WX"),
		Nickname:     values["nickname"],
		ExpiresAt:    time.Now().Unix() + expiresIn,
		ExpiresIn:    expiresIn,
	}, nil
}

// defaultString 是一个辅助函数，当输入字符串 s 为空时返回默认值 def，否则返回原字符串 s。
func defaultString(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// randomHex 生成指定长度 n 的随机字节序列，并将其编码为十六进制字符串，
// 用于生成唯一的会话 ID。
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
