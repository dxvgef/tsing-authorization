package service

import (
	"github.com/dxvgef/tsing"
)

func setRouter() {
	// 检查secret
	router := engine.Group("", CheckSecret)

	// 数据管理
	var dataHandler Data
	router.GET("/data/", dataHandler.OutputJSON)
	router.POST("/data/", dataHandler.LoadAll)
	router.PUT("/data/", dataHandler.SaveAll)

	// 规则管理
	var ruleHandler Rule
	router.POST("/rule/", ruleHandler.Add)           // 添加
	router.PUT("/rule/:name", ruleHandler.Put)       // 添加或更新
	router.DELETE("/rule/:name", ruleHandler.Delete) // 删除规则

	// 授权管理
	var authHandler Auth
	// 生成授权
	router.POST("/auth", authHandler.Sign)
	// 刷新授权
	router.PUT("/auth", func(ctx *tsing.Context) error {
		return nil
	})
	// 验证授权
	router.GET("/auth", authHandler.Verity)
}
