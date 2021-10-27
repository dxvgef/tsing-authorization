package main

import (
	"flag"

	"local/global"
	handler "local/service"

	"github.com/rs/zerolog/log"
)

func main() {
	// 设置默认logger
	global.SetDefaultLogger()

	// 解析启动参数
	flag.StringVar(&global.Config.ConfigFile, "c", global.Config.ConfigFile, "配置文件，默认值: config.toml")
	flag.Parse()

	// 加载配置
	if err := global.LoadConfig(); err != nil {
		log.Fatal().Err(err).Msg("加载配置失败")
	}

	// 根据配置设置logger
	if err := global.SetLogger(); err != nil {
		log.Fatal().Err(err).Msg("设置Logger失败")
	}

	// 启动服务
	handler.Start()
}
