package service

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"local/storage"

	"local/global"

	"github.com/dxvgef/tsing"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/http2"
)

var engine *tsing.Engine
var httpServer *http.Server
var httpsServer *http.Server

// 所有数据输出成JSON
func OutputJSON() ([]byte, error) {
	rules := make(map[string]global.Rule, global.SyncMapLen(&global.Rules))
	global.Rules.Range(func(key, value interface{}) bool {
		rules[key.(string)] = value.(global.Rule)
		return true
	})
	return json.Marshal(&rules)
}

// 配置服务引擎
func ConfigService() {
	var (
		err    error
		config tsing.Config
	)

	// 构建存储器
	if global.StorageInstance, err = storage.Build(global.Config.Storage.Name, global.Config.Storage.Config); err != nil {
		log.Fatal().Err(err).Caller().Msg("构建存储器实例失败")
		return
	}
	// 从存储器中加载所有规则
	if err = global.StorageInstance.LoadAllRule(); err != nil {
		log.Fatal().Err(err).Caller().Msg("从存储器加载数据失败")
		return
	}

	config.EventHandler = eventHandler
	config.Recover = global.Config.Service.Recover
	config.EventShortPath = global.Config.Service.EventShortPath
	config.EventSource = global.Config.Service.EventSource
	config.EventTrace = global.Config.Service.EventTrace
	config.EventHandlerError = true // 一定要处理handler返回的错误
	rootPath, err := os.Getwd()
	if err == nil {
		config.RootPath = rootPath + "/src/"
	}

	engine = tsing.New(&config)

	// 设置路由
	setRouter()

	// 设置HTTP服务
	if global.Config.Service.HTTPPort > 0 {
		httpServer = &http.Server{
			Addr:              global.Config.Service.IP + ":" + strconv.FormatUint(uint64(global.Config.Service.HTTPPort), 10),
			Handler:           engine,                                                               // 调度器
			ReadTimeout:       time.Duration(global.Config.Service.ReadTimeout) * time.Second,       // 读取超时
			WriteTimeout:      time.Duration(global.Config.Service.WriteTimeout) * time.Second,      // 响应超时
			IdleTimeout:       time.Duration(global.Config.Service.IdleTimeout) * time.Second,       // 连接空闲超时
			ReadHeaderTimeout: time.Duration(global.Config.Service.ReadHeaderTimeout) * time.Second, // http header读取超时
		}
	}

	// 设置HTTPS服务
	if global.Config.Service.HTTPSPort > 0 {
		httpsServer = &http.Server{
			Handler:           engine,
			Addr:              global.Config.Service.IP + ":" + strconv.FormatUint(uint64(global.Config.Service.HTTPSPort), 10),
			ReadTimeout:       time.Duration(global.Config.Service.ReadTimeout) * time.Second,       // 读取超时
			WriteTimeout:      time.Duration(global.Config.Service.WriteTimeout) * time.Second,      // 响应超时
			IdleTimeout:       time.Duration(global.Config.Service.IdleTimeout) * time.Second,       // 连接空闲超时
			ReadHeaderTimeout: time.Duration(global.Config.Service.ReadHeaderTimeout) * time.Second, // http header读取超时
		}
		if global.Config.Service.HTTP2 {
			if err = http2.ConfigureServer(httpsServer, &http2.Server{}); err != nil {
				log.Fatal().Err(err).Caller().Send()
				return
			}
		}
	}
}

func Start() {
	// 配置服务
	ConfigService()

	// 启动http服务
	if global.Config.Service.HTTPPort > 0 {
		go func() {
			log.Info().Msg("启动HTTP服务 " + httpServer.Addr)
			if err := httpServer.ListenAndServe(); err != nil {
				if err == http.ErrServerClosed {
					log.Info().Msg("HTTP服务已关闭")
					return
				}
				log.Fatal().Err(err).Caller().Msg("启动HTTPS服务失败")
			}
		}()
	}

	// 启动https服务
	if global.Config.Service.HTTPSPort > 0 {
		go func() {
			log.Info().Msg("启动HTTPS服务 " + httpsServer.Addr)
			if err := httpsServer.ListenAndServeTLS(global.Config.Service.HTTPSCert, global.Config.Service.HTTPSKey); err != nil {
				if err == http.ErrServerClosed {
					log.Info().Msg("HTTPS服务已关闭")
					return
				}
				log.Fatal().Err(err).Caller().Msg("启动HTTPS服务失败")
				return
			}
		}()
	}

	// 监听存储中的数据变更
	go func() {
		log.Info().Msg("开始监听数据变更")
		if err := global.StorageInstance.Watch(); err != nil {
			log.Fatal().Err(err).Caller().Msg("启动存储器监听失败")
			return
		}
	}()

	// 监听进程退出信号
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit

	// 退出http服务
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(global.Config.Service.QuitWaitTimeout)*time.Second)
	defer cancel()
	if httpServer != nil {
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Fatal().Caller().Msg(err.Error())
		}
	}

	// 退出https服务
	if httpsServer != nil {
		if err := httpsServer.Shutdown(ctx); err != nil {
			log.Fatal().Caller().Msg(err.Error())
		}
	}
}
