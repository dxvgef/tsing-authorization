package jwt_sm2

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"local/global"

	"github.com/rs/zerolog/log"
	"github.com/tjfoc/gmsm/sm2"
)

type Instance struct {
	Expires   int64           `json:"expires"`
	SM2Key    *sm2.PrivateKey `json:"-"`
	SM2KeyStr string          `json:"sm2_key"`
}

type _Claims struct {
	Expires   int64  `json:"expires,omitempty"`
	Aud       string `json:"aud,omitempty"`
	IP        string `json:"ip,omitempty"`
	TokenHash string `json:"token_hash,omitempty"`
}

func New(config string) (*Instance, error) {
	var instance Instance
	err := json.Unmarshal(global.StrToBytes(config), &instance)
	if err != nil {
		return nil, err
	}
	if instance.SM2KeyStr == "" {
		return nil, errors.New("private_key不能为空")
	}
	// 转换私钥
	instance.SM2Key, err = base64ToSM2PrivateKey(instance.SM2KeyStr)
	if err != nil {
		return nil, errors.New("无效的SM2私钥Base64字符串：" + err.Error())
	}

	return &instance, err
}

func (receiver *Instance) Sign(tokenHash string) (tokenStr string, err error) {
	var (
		claims      _Claims
		header      string
		claimsBytes []byte
		token       strings.Builder
		signBytes   []byte
	)
	if receiver.Expires > 0 {
		claims.Expires = time.Now().Add(time.Duration(receiver.Expires) * time.Second).Unix()
	}
	claims.TokenHash = tokenHash
	// header部份
	header = `{"alg":"SM2","typ":"JWT"}`
	// payload部份
	claimsBytes, err = json.Marshal(&claims)
	if err != nil {
		log.Err(err).Caller().Send()
		return
	}
	token.WriteString(base64.RawURLEncoding.EncodeToString(global.StrToBytes(header)))
	token.WriteString(".")
	token.WriteString(base64.RawURLEncoding.EncodeToString(claimsBytes))

	// 签名
	signBytes, err = receiver.SM2Key.Sign(rand.Reader, global.StrToBytes(token.String()), nil)
	if err != nil {
		log.Err(err).Caller().Send()
		return "", err
	}

	token.WriteString(".")
	token.WriteString(base64.RawURLEncoding.EncodeToString(signBytes))
	log.Debug().Str("token", token.String()).Caller().Send()
	tokenStr = token.String()
	return
}

func (receiver *Instance) VeritySign(tokenStr string) (global.UpdaterClaims, bool) {
	var claims global.UpdaterClaims
	jwtClaims, err := parseClaims(receiver.SM2Key, tokenStr)
	if err != nil {
		return claims, false
	}
	claims.Expires = jwtClaims.Expires
	claims.TokenHash = jwtClaims.TokenHash
	claims.Aud = jwtClaims.Aud
	claims.IP = jwtClaims.IP
	return claims, true
}

// base64转sm2私钥
func base64ToSM2PrivateKey(privateKeyStr string) (*sm2.PrivateKey, error) {
	var (
		err        error
		decoded    []byte
		privateKey *sm2.PrivateKey
	)
	decoded, err = base64.RawURLEncoding.DecodeString(privateKeyStr)
	if err != nil {
		return nil, err
	}
	privateKey, err = sm2.ParsePKCS8PrivateKey(decoded, nil)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func parseClaims(key *sm2.PrivateKey, tokenStr string) (claims _Claims, err error) {
	var claimsBytes, signBytes []byte
	arr := strings.Split(tokenStr, ".")
	if len(arr) != 3 {
		err = errors.New("token无效")
		log.Err(err).Caller().Send()
		return
	}
	claimsBytes, err = base64.RawURLEncoding.DecodeString(arr[1])
	if err != nil {
		log.Err(err).Caller().Send()
		return
	}
	signBytes, err = base64.RawURLEncoding.DecodeString(arr[2])
	if err != nil {
		log.Err(err).Caller().Send()
		return
	}
	msg := arr[0] + "." + arr[1]
	// 用私钥验签(也可以用公钥)
	if !key.Verify(global.StrToBytes(msg), signBytes) {
		err = errors.New("签名无效")
		log.Err(err).Caller().Send()
		return
	}
	// 解析claims
	if err = json.Unmarshal(claimsBytes, &claims); err != nil {
		log.Err(err).Caller().Send()
		return
	}
	return
}
