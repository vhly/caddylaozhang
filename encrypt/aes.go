package encrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(ResponseAesEncryptor{})
	httpcaddyfile.RegisterHandlerDirective("response_aesencryptor", parseCaddyfile)
}

// parseCaddyfile sets up the log_append handler from Caddyfile tokens. Syntax:
//
//	log_append [<matcher>] <key> <value>
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	handler := new(ResponseAesEncryptor)
	err := handler.UnmarshalCaddyfile(h.Dispenser)
	return handler, err
}

// ResponseEncryptor 实现HTTP响应体加密的中间件
type ResponseAesEncryptor struct {
	// 加密算法，支持 "aes-gcm", "aes-cbc"
	Algorithm string `json:"algorithm,omitempty"`

	// 加密密钥，base64编码
	Key string `json:"key,omitempty"`

	// 是否对所有响应加密，默认为true
	EncryptAll bool `json:"encrypt_all,omitempty"`

	// 需要加密的路径列表（当EncryptAll为false时生效）
	IncludePaths []string `json:"include_paths,omitempty"`

	// 排除加密的路径列表（当EncryptAll为true时生效）
	ExcludePaths []string `json:"exclude_paths,omitempty"`

	// 响应头中是否包含加密标记
	AddHeader bool `json:"add_header,omitempty"`

	logger *zap.Logger
	key    []byte
	nonce  []byte
}

// CaddyModule 返回模块信息
func (ResponseAesEncryptor) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.response_aesencryptor",
		New: func() caddy.Module { return new(ResponseAesEncryptor) },
	}
}

// Provision 设置模块
func (m *ResponseAesEncryptor) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)

	// 解码base64密钥
	if m.Key != "" {
		var err error
		m.key, err = base64.StdEncoding.DecodeString(m.Key)
		if err != nil {
			return err
		}

		// 根据算法设置nonce/IV大小
		switch m.Algorithm {
		case "aes-gcm":
			m.nonce = make([]byte, 12) // GCM标准nonce大小
		case "aes-cbc":
			m.nonce = make([]byte, aes.BlockSize) // CBC的IV大小
		case "":
			m.Algorithm = "aes-gcm" // 默认算法
			m.nonce = make([]byte, 12)
		default:
			// return caddy.Err("unsupported algorithm: " + m.Algorithm)
			return err
		}
	} else {
		return errors.New("encryption key is required")
	}

	return nil
}

// Validate 验证配置
func (m *ResponseAesEncryptor) Validate() error {
	if len(m.key) != 16 && len(m.key) != 24 && len(m.key) != 32 {
		return errors.New("encryption key must be 16, 24, or 32 bytes after base64 decoding")
	}
	return nil
}

// ServeHTTP 实现中间件逻辑
func (m ResponseAesEncryptor) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// 检查是否需要加密该路径
	if !m.shouldEncrypt(r.URL.Path) {
		return next.ServeHTTP(w, r)
	}

	// 创建响应记录器
	rec := &responseRecorder{
		ResponseWriter: w,
		body:           []byte{},
		statusCode:     http.StatusOK,
	}

	m.logger.Debug("ResponseAesEncryptor ServeHTTP prepare response")

	// 执行下一个处理器
	err := next.ServeHTTP(rec, r)
	if err != nil {
		return err
	}

	m.logger.Debug("ResponseAesEncryptor ServeHTTP encrypt start")

	// 加密响应体
	encryptedData, err := m.encryptData(rec.body)
	if err != nil {
		m.logger.Error("failed to encrypt response", zap.Error(err))
		return err
	}

	// 设置响应头
	if m.AddHeader {
		w.Header().Set("X-Content-Encrypted", "true")
		w.Header().Set("X-Encryption-Algorithm", m.Algorithm)
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", string(rune(len(encryptedData))))

	// 写入加密后的数据
	if rec.statusCode != 0 {
		w.WriteHeader(rec.statusCode)
	}

	_, writeErr := w.Write(encryptedData)
	if writeErr != nil {
		m.logger.Error("failed to write encrypted response", zap.Error(writeErr))
	}

	return nil
}

// shouldEncrypt 检查是否需要加密当前路径
func (m *ResponseAesEncryptor) shouldEncrypt(path string) bool {
	if m.EncryptAll {
		// 检查是否在排除列表中
		for _, excludePath := range m.ExcludePaths {
			if strings.HasPrefix(path, excludePath) {
				return false
			}
		}
		return true
	} else {
		// 检查是否在包含列表中
		for _, includePath := range m.IncludePaths {
			if strings.HasPrefix(path, includePath) {
				return true
			}
		}
		return false
	}
}

// encryptData 加密数据
func (m *ResponseAesEncryptor) encryptData(data []byte) ([]byte, error) {
	switch m.Algorithm {
	case "aes-gcm":
		return m.encryptAESGCM(data)
	case "aes-cbc":
		return m.encryptAESCBC(data)
	default:
		return nil, errors.New("unsupported algorithm")
	}
}

// encryptAESGCM 使用AES-GCM加密
func (m *ResponseAesEncryptor) encryptAESGCM(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// 生成随机nonce
	if _, err := io.ReadFull(rand.Reader, m.nonce); err != nil {
		return nil, err
	}

	// 加密数据
	encrypted := gcm.Seal(nil, m.nonce, data, nil)

	// 返回nonce + 加密数据（便于解密）
	result := make([]byte, len(m.nonce)+len(encrypted))
	copy(result, m.nonce)
	copy(result[len(m.nonce):], encrypted)

	return result, nil
}

// encryptAESCBC 使用AES-CBC加密
func (m *ResponseAesEncryptor) encryptAESCBC(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return nil, err
	}

	// 生成随机IV
	if _, err := io.ReadFull(rand.Reader, m.nonce); err != nil {
		return nil, err
	}

	// PKCS7填充
	data = m.pkcs7Pad(data, aes.BlockSize)

	// 加密数据
	encrypted := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, m.nonce)
	mode.CryptBlocks(encrypted, data)

	// 返回IV + 加密数据
	result := make([]byte, len(m.nonce)+len(encrypted))
	copy(result, m.nonce)
	copy(result[len(m.nonce):], encrypted)

	return result, nil
}

// pkcs7Pad 实现PKCS7填充
func (m *ResponseAesEncryptor) pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// UnmarshalCaddyfile 从Caddyfile解析配置
func (m *ResponseAesEncryptor) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "algorithm":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Algorithm = d.Val()

			case "key":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Key = d.Val()

			case "encrypt_all":
				if d.NextArg() {
					m.EncryptAll = d.Val() == "true"
				} else {
					m.EncryptAll = true
				}

			case "include_paths":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				m.IncludePaths = args

			case "exclude_paths":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				m.ExcludePaths = args

			case "add_header":
				if d.NextArg() {
					m.AddHeader = d.Val() == "true"
				} else {
					m.AddHeader = true
				}
			}
		}
	}
	return nil
}

// responseRecorder 用于记录HTTP响应
type responseRecorder struct {
	http.ResponseWriter
	body       []byte
	statusCode int
}

func (r *responseRecorder) Write(data []byte) (int, error) {
	r.body = append(r.body, data...)
	return len(data), nil
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
}

// 接口守卫
var (
	_ caddy.Provisioner           = (*ResponseAesEncryptor)(nil)
	_ caddy.Validator             = (*ResponseAesEncryptor)(nil)
	_ caddyhttp.MiddlewareHandler = (*ResponseAesEncryptor)(nil)
	_ caddyfile.Unmarshaler       = (*ResponseAesEncryptor)(nil)
)
