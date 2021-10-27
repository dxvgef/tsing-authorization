package sm2

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"local/global"

	"github.com/dxvgef/sm2lib"
	"github.com/rs/zerolog/log"
)

type Instance struct {
	Expires       int64              `json:"expires"`
	PrivateKey    *sm2lib.PrivateKey `json:"-"`
	PrivateKeyStr string             `json:"private_key"`
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
	if instance.PrivateKeyStr == "" {
		return nil, errors.New("private_key不能为空")
	}
	// 转换私钥
	err = instance.PrivateKey.FromBase64(base64.RawURLEncoding, []byte(instance.PrivateKeyStr), nil)
	if err != nil {
		return nil, errors.New("无效的SM2私钥Base64字符串：" + err.Error())
	}

	return &instance, err
}

func (inst *Instance) Sign(tokenHash string) (tokenStr string, err error) {
	var (
		claims      _Claims
		header      string
		claimsBytes []byte
		token       strings.Builder
		signBytes   []byte
	)
	if inst.Expires > 0 {
		claims.Expires = time.Now().Add(time.Duration(inst.Expires) * time.Second).Unix()
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
	signBytes, err = inst.PrivateKey.Sign([]byte(token.String()))
	if err != nil {
		log.Err(err).Caller().Send()
		return "", err
	}

	token.WriteString(".")
	token.WriteString(base64.RawURLEncoding.EncodeToString(signBytes))
	tokenStr = token.String()
	return
}

func (inst *Instance) VeritySign(tokenStr string) (global.UpdaterClaims, bool) {
	var claims global.UpdaterClaims
	jwtClaims, err := parseClaims(inst.PrivateKey.GetPublicKey(), tokenStr)
	if err != nil {
		return claims, false
	}
	claims.Expires = jwtClaims.Expires
	claims.TokenHash = jwtClaims.TokenHash
	claims.Aud = jwtClaims.Aud
	claims.IP = jwtClaims.IP
	return claims, true
}

func parseClaims(publicKey sm2lib.PublicKey, tokenStr string) (claims _Claims, err error) {
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
	if !publicKey.Verify(global.StrToBytes(msg), signBytes) {
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
