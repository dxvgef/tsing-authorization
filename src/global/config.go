package global

import (
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml"
	"github.com/rs/zerolog/log"
)

var Config struct {
	// 配置文件路径
	ConfigFile string `json:"-" toml:"-"`

	// 服务参数
	Service struct {
		Secret                string `json:"secret" toml:"secret"`
		IP                    string `json:"-" toml:"-"`
		HTTPPort              uint16 `json:"http_port" toml:"http_port"`
		HTTPSPort             uint16 `json:"https_port" toml:"https_port"`
		HTTPSCert             string `json:"https_cert" toml:"https_cert"`
		HTTPSKey              string `json:"https_key" toml:"https_key"`
		ReadTimeout           uint   `json:"read_timeout" toml:"read_timeout"`
		ReadHeaderTimeout     uint   `json:"read_header_timeout" toml:"read_header_timeout"`
		WriteTimeout          uint   `json:"write_timeout" toml:"write_timeout"`
		IdleTimeout           uint   `json:"idle_timeout" toml:"idle_timeout"`
		QuitWaitTimeout       uint   `json:"quit_wait_timeout" toml:"quit_wait_timeout"`
		HTTP2                 bool   `json:"http2" toml:"http2"`
		Debug                 bool   `json:"-" toml:"debug"`
		EventSource           bool   `json:"event_source" toml:"event_source"`
		EventTrace            bool   `json:"event_trace" toml:"event_trace"`
		EventNotFound         bool   `json:"event_not_found" toml:"event_not_found"`
		EventMethodNotAllowed bool   `json:"event_method_not_allowed" toml:"event_method_not_allowed"`
		Recover               bool   `json:"-" toml:"-"`
		EventShortPath        bool   `json:"event_short_path" toml:"event_short_path"`
	} `json:"service" toml:"service"`

	// 日志配置
	Logger struct {
		Level      string      `json:"level" toml:"level"`
		FilePath   string      `json:"file_path" toml:"file_path"`
		Encode     string      `json:"encode" toml:"encode"`
		TimeFormat string      `json:"time_format" toml:"time_format"`
		FileMode   os.FileMode `json:"file_mode" toml:"file_mode"`
		NoColor    bool        `json:"no_color" toml:"no_color"`
	} `json:"logger" toml:"logger"`

	// 存储配置
	Storage struct {
		Name   string `json:"-" toml:"name"`
		Config string `json:"config" toml:"config"`
	} `json:"storage" toml:"storage"`
}

// 加载本地默认配置
func loadDefault() {
	// 服务默认配置
	Config.Service.ReadTimeout = 10
	Config.Service.ReadHeaderTimeout = 10
	Config.Service.WriteTimeout = 10
	Config.Service.IdleTimeout = 10
	Config.Service.QuitWaitTimeout = 5
	Config.Service.Debug = true
	Config.Service.HTTPPort = 80
	Config.Service.Recover = true
	Config.Service.EventSource = true
	Config.Service.EventTrace = false
	Config.Service.EventNotFound = true
	Config.Service.EventMethodNotAllowed = true
	Config.Service.EventShortPath = true

	// 日志默认配置
	Config.Logger.Level = "debug"
	Config.Logger.FileMode = 600
	Config.Logger.Encode = "console"
	Config.Logger.TimeFormat = "y-m-d h:i:s"
}

// 加载配置
func LoadConfig() error {
	loadDefault()

	file, err := os.Open(filepath.Clean(Config.ConfigFile))
	if err != nil {
		log.Fatal().Err(err).Caller().Send()
		return err
	}

	// 解析配置文件到结构体
	err = toml.NewDecoder(file).Decode(&Config)
	if err != nil {
		log.Fatal().Err(err).Caller().Send()
		return err
	}

	log.Info().Msg("配置文件加载成功")

	return nil
}
