package service

import (
	"encoding/json"
	"local/authorizer"
	"local/global"
	"local/updater"

	"github.com/dxvgef/filter/v2"
	"github.com/dxvgef/tsing"
	"github.com/rs/zerolog/log"
)

// 规则管理
type Rule struct{}

// 添加规则
func (self *Rule) Add(ctx *tsing.Context) error {
	var (
		err                             error
		resp                            = make(map[string]string)
		rule                            global.Rule
		authorizerConfig, updaterConfig string
	)
	if err = filter.Batch(
		filter.String(ctx.Post("name"), "name").Require().Set(&rule.Name),
		filter.String(ctx.Post("authorizer"), "authorizer").Require().IsJSON().Set(&authorizerConfig),
		filter.String(ctx.Post("updater"), "updater").IsJSON().Set(&updaterConfig),
	); err != nil {
		resp["error"] = err.Error()
		return JSON(ctx, 400, &resp)
	}
	// 判断规则是否存在
	if _, exists := global.Rules.Load(rule.Name); exists {
		resp["error"] = "规则已存在"
		return JSON(ctx, 400, &resp)
	}
	// 解析授权器配置
	if err = json.Unmarshal(global.StrToBytes(authorizerConfig), &rule.Authorizer); err != nil {
		log.Err(err).Caller().Msg("解析authorizer配置失败")
		return err
	}
	// 构建授权器实例
	rule.Authorizer.Instance, err = authorizer.Build(rule.Authorizer.Type, rule.Authorizer.Config)
	if err != nil {
		log.Err(err).Caller().Msg("构建authorizer实例失败")
		return err
	}
	if updaterConfig != "" {
		// 解析授权器配置
		if err = json.Unmarshal(global.StrToBytes(updaterConfig), &rule.Updater); err != nil {
			log.Err(err).Caller().Msg("解析updater配置失败")
			return err
		}
		if rule.Updater.Type != "" {
			// 构建授权器实例
			rule.Updater.Instance, err = updater.Build(rule.Updater.Type, rule.Updater.Config)
			if err != nil {
				log.Err(err).Caller().Msg("构建updater实例失败")
				return err
			}
		}
	}
	// 将规则保存到存储器
	if err = global.StorageInstance.SaveRule(rule); err != nil {
		log.Err(err).Caller().Send()
		resp["error"] = err.Error()
		return JSON(ctx, 500, &resp)
	}
	return Status(ctx, 204)
}

// 添加或替换规则
func (self *Rule) Put(ctx *tsing.Context) error {
	var (
		err                             error
		resp                            = make(map[string]string)
		rule                            global.Rule
		authorizerConfig, updaterConfig string
	)
	if err = filter.Batch(
		filter.String(ctx.PathParams.Value("name"), "name").Require().Base64RawURLDecode().Set(&rule.Name),
		filter.String(ctx.Post("authorizer"), "authorizer").Require().IsJSON().Set(&authorizerConfig),
		filter.String(ctx.Post("updater"), "updater").IsJSON().Set(&updaterConfig),
	); err != nil {
		resp["error"] = err.Error()
		return JSON(ctx, 400, &resp)
	}
	// 解析授权器配置
	if err = json.Unmarshal(global.StrToBytes(authorizerConfig), &rule.Authorizer); err != nil {
		log.Err(err).Caller().Msg("解析authorizer配置失败")
		return err
	}
	// 构建授权器实例
	rule.Authorizer.Instance, err = authorizer.Build(rule.Authorizer.Type, rule.Authorizer.Config)
	if err != nil {
		log.Err(err).Caller().Msg("构建authorizer实例失败")
		return err
	}
	if updaterConfig != "" {
		// 解析授权器配置
		if err = json.Unmarshal(global.StrToBytes(updaterConfig), &rule.Updater); err != nil {
			log.Err(err).Caller().Msg("解析updater配置失败")
			return err
		}
		if rule.Updater.Type != "" {
			// 构建授权器实例
			rule.Updater.Instance, err = updater.Build(rule.Updater.Type, rule.Updater.Config)
			if err != nil {
				log.Err(err).Caller().Msg("构建updater实例失败")
				return err
			}
		}
	}
	// 将规则保存到存储器
	if err = global.StorageInstance.SaveRule(rule); err != nil {
		log.Err(err).Caller().Send()
		resp["error"] = err.Error()
		return JSON(ctx, 500, &resp)
	}
	return Status(ctx, 204)
}

// 删除规则
func (self *Rule) Delete(ctx *tsing.Context) error {
	var (
		err  error
		resp = make(map[string]string)
		name string
	)
	name, err = filter.String(ctx.PathParams.Value("name"), "name").Require().Base64RawURLDecode().String()
	if err != nil {
		resp["error"] = err.Error()
		return JSON(ctx, 400, &resp)
	}
	// 判断规则是否存在
	if _, exists := global.Rules.Load(name); !exists {
		return Status(ctx, 204)
	}
	// 从存储器中删除规则
	if err = global.StorageInstance.DeleteRule(ctx.PathParams.Value("name")); err != nil {
		log.Err(err).Caller().Send()
		resp["error"] = err.Error()
		return JSON(ctx, 500, &resp)
	}
	return Status(ctx, 204)
}
