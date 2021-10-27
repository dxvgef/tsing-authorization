package etcd

import (
	"context"
	"strings"

	"local/global"

	"github.com/rs/zerolog/log"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// 监听变更
func (self *Etcd) Watch() error {
	ch := self.client.Watch(context.Background(), self.KeyPrefix+"/", clientv3.WithPrefix())
	for resp := range ch {
		for k := range resp.Events {
			switch resp.Events[k].Type {
			// 更新事件
			case clientv3.EventTypePut:
				if err := self.watchLoadData(resp.Events[k].Kv.Key, resp.Events[k].Kv.Value); err != nil {
					log.Err(err).Caller().Send()
				}
			// 删除事件
			case clientv3.EventTypeDelete:
				if err := self.watchDeleteData(resp.Events[k].Kv.Key); err != nil {
					log.Err(err).Caller().Send()
				}
			}
		}
	}
	return nil
}

// 监听存储器数据更新，同步本地数据
func (self *Etcd) watchLoadData(key, value []byte) error {
	keyStr := global.BytesToStr(key)
	// 加载规则
	if strings.HasPrefix(keyStr, self.KeyPrefix+"/rules/") {
		return self.LoadRule(value)
	}
	return nil
}

// 监听存储器数据删除，同步本地数据
func (self *Etcd) watchDeleteData(key []byte) error {
	keyStr := global.BytesToStr(key)
	if strings.HasPrefix(keyStr, self.KeyPrefix+"/rules/") {
		return global.DeleteRule(keyStr)
	}
	return nil
}
