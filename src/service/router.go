package service

func setRouter() {
	// 检查secret
	router := engine.Group("", CheckSecret)

	// 数据管理
	var dataHandler Data
	router.GET("/data/", dataHandler.OutputJSON) // 输出所有配置
	router.POST("/data/", dataHandler.LoadAll)   // 从存储器加载所有配置
	router.PUT("/data/", dataHandler.SaveAll)    // 将所有配置保存到存储器

	// 规则管理
	var ruleHandler Rule
	router.POST("/rule/", ruleHandler.Add)           // 添加
	router.PUT("/rule/:name", ruleHandler.Put)       // 添加或更新
	router.DELETE("/rule/:name", ruleHandler.Delete) // 删除规则

	// 授权管理
	var authHandler Auth
	router.POST("/auth", authHandler.Sign)   // 生成授权
	router.PUT("/auth", authHandler.Refresh) // 刷新授权
	router.GET("/auth", authHandler.Verity)  // 验证授权
}
