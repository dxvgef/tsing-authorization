package service

import (
	"local/global"

	"github.com/dxvgef/tsing"
)

func CheckSecret(ctx *tsing.Context) error {
	if ctx.Request.Header.Get("SECRET") != global.Config.Service.Secret {
		ctx.Abort()
		return Status(ctx, 401)
	}
	return nil
}
