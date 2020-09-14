package service

import (
	"errors"
	"time"

	"local/global"

	"github.com/dxvgef/gommon/encrypt"

	"github.com/dxvgef/filter/v2"
	"github.com/dxvgef/tsing"
)

// 授权管理
type Auth struct{}

// 签发授权
func (self *Auth) Sign(ctx *tsing.Context) error {
	var (
		err                                  error
		resp                                 = make(map[string]string)
		name                                 string
		payload                              string
		tokenStr, refreshTokenStr, tokenHash string
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
	tokenStr, err = rule.Authorizer.Instance.Sign(global.SignParams{})
	if err != nil {
		resp["error"] = "签发授权失败：" + err.Error()
		return JSON(ctx, 400, &resp)
	}
	resp["token"] = tokenStr

	// 使用规则的更新器实例生成refresh token
	if rule.Updater.Type != "" {
		// 计算access token的hash
		tokenHash, err = encrypt.MD5ByStr(tokenStr)
		if err != nil {
			resp["error"] = "Token Hash计算失败：" + err.Error()
			return JSON(ctx, 400, &resp)
		}
		refreshTokenStr, err = rule.Updater.Instance.Sign(tokenHash)
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
		err  error
		resp = make(map[string]interface{})
		name string
		// scopes   []string
		tokenStr string
	)
	if err = filter.Batch(
		filter.String(ctx.Query("name"), "name").Require().Set(&name),
		// filter.String(ctx.Query("scope"), "scope").SetSlice(&scopes, ","),
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
	claims, valid := rule.Authorizer.Instance.VeritySign(tokenStr)
	if !valid {
		resp["error"] = "签名验证失败"
		return JSON(ctx, 400, &resp)
	}
	if claims.Expires != 0 && claims.Expires <= time.Now().Unix() {
		resp["error"] = "授权已过期"
		return JSON(ctx, 400, &resp)
	}

	return JSON(ctx, 200, &resp)
}

// 刷新授权
func (self *Auth) Refresh(ctx *tsing.Context) error {
	var (
		err                                                                   error
		resp                                                                  = make(map[string]string)
		name                                                                  string
		tokenStr, refreshTokenStr, newTokenStr, newRefreshTokenStr, tokenHash string
		valid                                                                 bool
		refreshClaims                                                         global.UpdaterClaims
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

	// 验证签名并获得claims
	_, valid = rule.Authorizer.Instance.VeritySign(tokenStr)
	if !valid {
		resp["error"] = "授权签名无效"
		return JSON(ctx, 400, &resp)
	}
	// 验证签名并获得刷新token的claims
	refreshClaims, valid = rule.Updater.Instance.VeritySign(refreshTokenStr)
	if !valid {
		resp["error"] = "刷新授权签名无效"
		return JSON(ctx, 400, &resp)
	}
	if refreshClaims.Expires != 0 && refreshClaims.Expires <= time.Now().Unix() {
		resp["error"] = "刷新授权已过期"
		return JSON(ctx, 400, &resp)
	}

	// 签发新的token
	newTokenStr, err = rule.Authorizer.Instance.Sign(global.SignParams{})
	if err != nil {
		resp["error"] = "签发授权失败：" + err.Error()
		return JSON(ctx, 400, &resp)
	}
	resp["token"] = newTokenStr

	// 签发新的refresh token
	if rule.Updater.Type != "" {
		// 计算access token的hash
		tokenHash, err = encrypt.MD5ByStr(tokenStr)
		if err != nil {
			resp["error"] = "Token Hash计算失败：" + err.Error()
			return JSON(ctx, 400, &resp)
		}
		newRefreshTokenStr, err = rule.Updater.Instance.Sign(tokenHash)
		if err != nil {
			resp["error"] = "签发刷新授权失败：" + err.Error()
			return JSON(ctx, 400, &resp)
		}
		resp["refresh_token"] = newRefreshTokenStr
	}

	return JSON(ctx, 200, &resp)
}
