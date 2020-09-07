package jwt_hs256

import (
	"encoding/json"
	"local/global"
	"time"

	"github.com/pascaldekloe/jwt"
	"github.com/rs/zerolog/log"
)

type Instance struct {
	Expires int64  `json:"expires"`
	Secret  string `json:"secret"`
}

func New(config string) (*Instance, error) {
	var instance Instance
	err := json.Unmarshal(global.StrToBytes(config), &instance)
	return &instance, err
}

func (receiver *Instance) Sign() (tokenStr string, err error) {
	var (
		claims     jwt.Claims
		tokenBytes []byte
	)
	if receiver.Expires > 0 {
		claims.Expires = jwt.NewNumericTime(time.Now().Add(time.Duration(receiver.Expires) * time.Second))
	}
	tokenBytes, err = claims.HMACSign(jwt.HS256, global.StrToBytes(receiver.Secret))
	if err != nil {
		log.Err(err).Caller().Send()
		return
	}
	tokenStr = global.BytesToStr(tokenBytes)
	return
}

func (receiver *Instance) Verity(tokenStr string) bool {
	// 解密得到claims
	claims, err := jwt.HMACCheck(global.StrToBytes(tokenStr), global.StrToBytes(receiver.Secret))
	if err != nil {
		return false
	}
	// 验证claims的expires
	if time.Now().Unix() > claims.Expires.Time().Unix() {
		return false
	}
	return true
}
