package etcd

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"local/authorizer"
	"local/global"
	"local/updater"

	"github.com/rs/zerolog/log"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// 从存储器加载规则数据到本地
func (self *Etcd) LoadRule(data []byte) error {
	var rule global.Rule
	err := json.Unmarshal(data, &rule)
	if err != nil {
		log.Err(err).Caller().Send()
		return err
	}
	// 构建授权器实例
	rule.Authorizer.Instance, err = authorizer.Build(rule.Authorizer.Type, rule.Authorizer.Config)
	if err != nil {
		log.Err(err).Caller().Msg("构建授权器实例失败")
		return err
	}
	//构建更新器的实例
	if rule.Updater.Type != "" {
		rule.Updater.Instance, err = updater.Build(rule.Updater.Type, rule.Updater.Config)
		if err != nil {
			log.Err(err).Caller().Msg("构建更新器实例失败")
			return err
		}
	}
	// 将规则写入到本地
	global.Rules.Store(rule.Name, rule)
	return nil
}

// 从存储器加载所有规则数据到本地
func (self *Etcd) LoadAllRule() error {
	var key strings.Builder
	key.WriteString(self.KeyPrefix)
	key.WriteString("/rules/")

	// 获取规则
	ctx, ctxCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer ctxCancel()
	resp, err := self.client.Get(ctx, key.String(), clientv3.WithPrefix())
	if err != nil {
		log.Err(err).Caller().Send()
		return err
	}
	for k := range resp.Kvs {
		err = self.LoadRule(resp.Kvs[k].Value)
		if err != nil {
			log.Err(err).Caller().Send()
			return err
		}
	}
	return nil
}

// 将本地规则数据保存到存储器
func (self *Etcd) SaveRule(rule global.Rule) error {
	var key strings.Builder
	key.WriteString(self.KeyPrefix)
	key.WriteString("/rules/")
	key.WriteString(global.EncodeKey(rule.Name))

	ruleBytes, err := json.Marshal(&rule)
	if err != nil {
		log.Err(err).Caller().Send()
		return err
	}

	ctx, ctxCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer ctxCancel()
	if _, err := self.client.Put(ctx, key.String(), global.BytesToStr(ruleBytes)); err != nil {
		log.Err(err).Caller().Send()
		return err
	}
	return nil
}

// 将本地所有规则数据保存到存储器
func (self *Etcd) SaveAllRule() error {
	var (
		err         error
		key         strings.Builder
		rules       = make(map[string]string, global.SyncMapLen(&global.Rules))
		configBytes []byte
	)

	// 将数据保存到临时变量中
	global.Rules.Range(func(k, v interface{}) bool {
		rule, ok := v.(global.Rule)
		if !ok {
			log.Error().Caller().Msg("类型断言失败")
			return false
		}
		if configBytes, err = json.Marshal(&rule); err != nil {
			log.Err(err).Caller().Send()
			return false
		}
		rules[k.(string)] = global.BytesToStr(configBytes)
		return true
	})

	// 清空存储器中的配置
	key.WriteString(self.KeyPrefix)
	key.WriteString("/rules/")
	ctx, ctxCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer ctxCancel()
	_, err = self.client.Delete(ctx, key.String(), clientv3.WithPrefix())
	if err != nil {
		log.Err(err).Caller().Send()
		return err
	}

	return nil
}

// 删除存储器的规则数据
func (self *Etcd) DeleteRule(name string) error {
	var key strings.Builder
	key.WriteString(self.KeyPrefix)
	key.WriteString("/rules/")
	key.WriteString(name)
	ctx, ctxCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer ctxCancel()
	_, err := self.client.Delete(ctx, key.String())
	if err != nil {
		log.Err(err).Caller().Send()
		return err
	}
	return nil
}
