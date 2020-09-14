package global

import (
	"sync"
)

var (
	StorageInstance Storage // 存储器实例

	Rules sync.Map // 规则集，key=名称, value=Rule{}
)

// 规则
type Rule struct {
	Name       string `json:"name"`
	Authorizer struct {
		Type     string             `json:"type"`
		Config   string             `json:"config"`
		Instance AuthorizerInstance `json:"-"`
	} `json:"authorizer"`
	Updater struct {
		Type     string          `json:"type"`
		Config   string          `json:"config"`
		Instance UpdaterInstance `json:"-"`
	} `json:"updater"`
}

// 签名参数
type SignParams struct {
	Expires int64
	Payload string
	Aud     string
	IP      string
}

type AuthorizerClaims struct {
	Expires int64
	Payload string
	Aud     string
	IP      string
}

type AuthorizerInstance interface {
	Sign(SignParams) (string, error)            // 签发授权
	VeritySign(string) (AuthorizerClaims, bool) // 验证签名
}

// 更新器
type UpdaterClaims struct {
	TokenHash string
	Expires   int64
	Aud       string
	IP        string
}

type UpdaterInstance interface {
	Sign(string) (string, error)             // 签发授权
	VeritySign(string) (UpdaterClaims, bool) // 验证签名
}

// 存储器
type Storage interface {
	// LoadAll() error // 从存储器加载所有数据到本地
	// SaveAll() error // 将本地所有数据保存到存储器

	LoadAllRule() error      // 从存储器加载所有规则到本地
	LoadRule([]byte) error   // 从存储器加载单个规则数据
	SaveAllRule() error      // 将本地所有规则数据保存到存储器
	SaveRule(Rule) error     // 将本地单个规则数据保存到存储器
	DeleteRule(string) error // 删除存储器中单个规则数据

	Watch() error // 监听存储器的数据变更
}
