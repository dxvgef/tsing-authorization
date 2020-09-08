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

func (receiver *Instance) Sign(payload string) (tokenStr string, err error) {
	var (
		claims     jwt.Claims
		tokenBytes []byte
	)
	if receiver.Expires > 0 {
		claims.Expires = jwt.NewNumericTime(time.Now().Add(time.Duration(receiver.Expires) * time.Second))
	}
	if payload != "" {
		claims.Set = make(map[string]interface{}, 1)
		claims.Set["payload"] = payload
		//if err = json.Unmarshal(global.StrToBytes(payload), &claims.Set); err != nil {
		//	err = errors.New("无法使用JSON编码payload参数值")
		//	return
		//}
	}
	tokenBytes, err = claims.RSASign(jwt.RS256, receiver.PrivateKey)
	if err != nil {
		log.Err(err).Caller().Send()
		return
	}
	tokenStr = global.BytesToStr(tokenBytes)
	return
}

func (receiver *Instance) Verity(tokenStr string) bool {
	// 解密得到claims
	claims, err := jwt.RSACheck(global.StrToBytes(tokenStr), receiver.PublicKey)
	if err != nil {
		log.Debug().Err(err).Caller().Send()
		return false
	}
	// 验证claims的expires
	if time.Now().Unix() > claims.Expires.Time().Unix() {
		return false
	}
	return true
}

func (receiver *Instance) GetPayload(tokenStr string) (string, bool) {
	// 解密得到claims
	claims, err := jwt.RSACheck(global.StrToBytes(tokenStr), receiver.PublicKey)
	if err != nil {
		return "", false
	}
	return claims.String("payload")
}
