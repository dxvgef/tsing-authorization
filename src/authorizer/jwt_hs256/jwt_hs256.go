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

func (receiver *Instance) Sign(params global.SignParams) (tokenStr string, err error) {
	var (
		claims     jwt.Claims
		tokenBytes []byte
	)
	if receiver.Expires > 0 {
		claims.Expires = jwt.NewNumericTime(time.Now().Add(time.Duration(receiver.Expires) * time.Second))
	}
	claims.Set = make(map[string]interface{})
	if params.Payload != "" {
		claims.Set["payload"] = params.Payload
	}
	if params.Aud != "" {
		claims.Set["aud"] = params.Aud
	}
	if params.IP != "" {
		claims.Set["ip"] = params.IP
	}
	tokenBytes, err = claims.HMACSign(jwt.HS256, global.StrToBytes(receiver.Secret))
	if err != nil {
		log.Err(err).Caller().Send()
		return
	}
	tokenStr = global.BytesToStr(tokenBytes)
	return
}

func (receiver *Instance) VeritySign(tokenStr string) (global.AuthorizerClaims, bool) {
	var claims global.AuthorizerClaims
	// 解密得到claims
	jwtClaims, err := jwt.HMACCheck(global.StrToBytes(tokenStr), global.StrToBytes(receiver.Secret))
	if err != nil {
		return claims, false
	}
	claims.Expires = jwtClaims.Expires.Time().Unix()
	claims.Payload, _ = jwtClaims.String("payload")
	claims.Aud, _ = jwtClaims.String("aud")
	claims.IP, _ = jwtClaims.String("ip")
	return claims, true
}
