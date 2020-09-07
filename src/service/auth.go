package service

import (
	"errors"
	"local/global"

	"github.com/dxvgef/filter/v2"
	"github.com/dxvgef/tsing"
)

// 授权管理
type Auth struct{}

// 签发授权
func (self *Auth) Sign(ctx *tsing.Context) error {
	var (
		err                       error
		resp                      = make(map[string]string)
		name                      string
		payload                   string
		tokenStr, refreshTokenStr string
	)
	if err = filter.Batch(
		filter.String(ctx.Post("name"), "name").Require().Set(&name),
		filter.String(ctx.Post("payload"), "payload").Set(&payload),
	); err != nil {
		resp["error"] = err.Error()
		return JSON(ctx, 400, &resp)
	}
	// 判断规则是否存在
	value, exists := global.Rules.Load(name)
	if !exists {
		resp["error"] = "规则不存在"
		return JSON(ctx, 400, &resp)
	}
	rule, ok := value.(global.Rule)
	if !ok {
		return errors.New("规则类型断言失败")
	}

	// 使用规则的授权器实例生成access token
	tokenStr, err = rule.Authorizer.Instance.Sign(payload)
	if err != nil {
		resp["error"] = "签发授权失败：" + err.Error()
		return JSON(ctx, 400, &resp)
	}
	resp["token"] = tokenStr

	// 使用规则的更新器实例生成refresh token
	if rule.Updater.Type != "" {
		refreshTokenStr, err = rule.Updater.Instance.Sign()
		if err != nil {
			resp["error"] = "签发刷新授权失败：" + err.Error()
			return JSON(ctx, 400, &resp)
		}
		resp["refresh_token"] = refreshTokenStr
	}
	return JSON(ctx, 200, &resp)
}

// 验证授权
func (self *Auth) Verity(ctx *tsing.Context) error {
	var (
		err      error
		resp     = make(map[string]interface{})
		name     string
		tokenStr string
	)
	if err = filter.Batch(
		filter.String(ctx.Query("name"), "name").Require().Set(&name),
		filter.String(ctx.Query("token"), "token").Require().Set(&tokenStr),
	); err != nil {
		resp["error"] = err.Error()
		return JSON(ctx, 400, &resp)
	}
	// 判断规则是否存在
	value, exists := global.Rules.Load(name)
	if !exists {
		resp["error"] = "规则不存在"
		return JSON(ctx, 400, &resp)
	}
	rule, ok := value.(global.Rule)
	if !ok {
		return errors.New("规则类型断言失败")
	}

	// 验证token
	resp["result"] = rule.Authorizer.Instance.Verity(tokenStr)
	return JSON(ctx, 200, &resp)
}

// 刷新授权
func (self *Auth) Refresh(ctx *tsing.Context) error {
	var (
		err                                                        error
		resp                                                       = make(map[string]string)
		name                                                       string
		tokenStr, refreshTokenStr, newTokenStr, newRefreshTokenStr string
	)
	if err = filter.Batch(
		filter.String(ctx.Post("name"), "name").Require().Set(&name),
		filter.String(ctx.Post("token"), "token").Require().Set(&tokenStr),
		filter.String(ctx.Post("refresh_token"), "refresh_token").Require().Set(&refreshTokenStr),
	); err != nil {
		resp["error"] = err.Error()
		return JSON(ctx, 400, &resp)
	}
	// 判断规则是否存在
	value, exists := global.Rules.Load(name)
	if !exists {
		resp["error"] = "规则不存在"
		return JSON(ctx, 400, &resp)
	}
	rule, ok := value.(global.Rule)
	if !ok {
		return errors.New("规则类型断言失败")
	}

	// 获取token的payload，同时可以证明该token来源合法，只是不验证到期时间
	payload, exist := rule.Authorizer.Instance.GetPayload(tokenStr)
	if !exist {
		resp["error"] = "token无效"
		return JSON(ctx, 400, &resp)
	}
	// 验证刷新token
	if !rule.Updater.Instance.Verity(refreshTokenStr) {
		resp["error"] = "refresh_token无效"
		return JSON(ctx, 400, &resp)
	}

	// 签发新的token
	newTokenStr, err = rule.Authorizer.Instance.Sign(payload)
	if err != nil {
		resp["error"] = "签发授权失败：" + err.Error()
		return JSON(ctx, 400, &resp)
	}
	resp["token"] = newTokenStr

	// 签发新的refresh token
	if rule.Updater.Type != "" {
		newRefreshTokenStr, err = rule.Updater.Instance.Sign()
		if err != nil {
			resp["error"] = "签发刷新授权失败：" + err.Error()
			return JSON(ctx, 400, &resp)
		}
		resp["refresh_token"] = newRefreshTokenStr
	}

	return JSON(ctx, 200, &resp)
}
