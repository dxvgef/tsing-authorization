package jwt_rs256

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"local/global"
	"time"

	"github.com/dxvgef/gommon/encrypt"
	"github.com/pascaldekloe/jwt"
	"github.com/rs/zerolog/log"
)

type Instance struct {
	Expires       int64           `json:"expires"`
	PublicKeyStr  string          `json:"public_key"`
	PublicKey     *rsa.PublicKey  `json:"-"`
	PrivateKey    *rsa.PrivateKey `json:"-"`
	PrivateKeyStr string          `json:"private_key"`
}

func New(config string) (*Instance, error) {
	var instance Instance
	err := json.Unmarshal(global.StrToBytes(config), &instance)
	if err != nil {
		return nil, err
	}
	if instance.PublicKeyStr == "" {
		return nil, errors.New("public_key不能为空")
	}
	if instance.PrivateKeyStr == "" {
		return nil, errors.New("private_key不能为空")
	}
	// 转换公钥
	instance.PublicKey, err = encrypt.Base64ToRSAPublicKey(instance.PublicKeyStr)
	if err != nil {
		return nil, errors.New("无效的公钥Base64字符串：" + err.Error())
	}
	// 转换私钥
	instance.PrivateKey, _, err = encrypt.Base64ToRSAPrivateKey(instance.PrivateKeyStr)
	if err != nil {
		return nil, errors.New("无效的私钥Base64字符串：" + err.Error())
	}

	return &instance, err
}

func (receiver *Instance) Sign(tokenHash string) (tokenStr string, err error) {
	var (
		claims     jwt.Claims
		tokenBytes []byte
	)
	if receiver.Expires > 0 {
		claims.Expires = jwt.NewNumericTime(time.Now().Add(time.Duration(receiver.Expires) * time.Second))
	}
	claims.Set = make(map[string]interface{}, 1)
	claims.Set["token_hash"] = tokenHash
	tokenBytes, err = claims.RSASign(jwt.RS256, receiver.PrivateKey)
	if err != nil {
		log.Err(err).Caller().Send()
		return
	}
	tokenStr = global.BytesToStr(tokenBytes)
	return
}

func (receiver *Instance) VeritySign(tokenStr string) (global.UpdaterClaims, bool) {
	var claims global.UpdaterClaims
	// 解密得到claims
	jwtClaims, err := jwt.RSACheck(global.StrToBytes(tokenStr), receiver.PublicKey)
	if err != nil {
		log.Debug().Err(err).Caller().Send()
		return claims, false
	}
	claims.Expires = jwtClaims.Expires.Time().Unix()
	claims.TokenHash, _ = jwtClaims.String("token_hash")
	claims.Aud, _ = jwtClaims.String("aud")
	claims.IP, _ = jwtClaims.String("ip")
	return claims, true
}
