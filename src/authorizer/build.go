package authorizer

import (
	"errors"
	hs256 "local/authorizer/jwt_hs256"
	"strings"

	"local/global"

	"github.com/rs/zerolog/log"
)

// 构建授权器实例
func Build(name, config string) (global.AuthorizerInstance, error) {
	name = strings.ToUpper(name)
	switch name {
	case "JWT_HS256":
		instance, err := hs256.New(config)
		if err != nil {
			log.Err(err).Caller().Send()
			return nil, err
		}
		return instance, nil
	}
	return nil, errors.New("不支持的规则类型")
}
