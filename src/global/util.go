package global

import (
	"encoding/base64"
	"path"
	"sync"
	"unsafe"

	"github.com/rs/zerolog/log"
)

func BytesToStr(value []byte) string {
	return *(*string)(unsafe.Pointer(&value)) // nolint
}

func StrToBytes(s string) []byte {
	x := (*[2]uintptr)(unsafe.Pointer(&s)) // nolint
	h := [3]uintptr{x[0], x[1], x[1]}
	return *(*[]byte)(unsafe.Pointer(&h)) // nolint
}

// 编码键名
func EncodeKey(value string) string {
	return base64.RawURLEncoding.EncodeToString(StrToBytes(value))
}

// 解码键名
func DecodeKey(value string) (string, error) {
	keyBytes, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		// 由于数据来自客户端，因此不记录日志
		return "", err
	}
	return BytesToStr(keyBytes), nil
}

// 计算sync.Map的长度
func SyncMapLen(m *sync.Map) (count int) {
	if m == nil {
		return
	}
	m.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return
}

// 清空sync.Map
func SyncMapClean(m *sync.Map) {
	if m == nil {
		return
	}
	m.Range(func(key, _ interface{}) bool {
		m.Delete(key)
		return true
	})
}

// 删除规则数据
func DeleteRule(key string) error {
	name, err := DecodeKey(path.Base(key))
	if err != nil {
		log.Err(err).Caller().Send()
		return err
	}
	Rules.Delete(name)
	return nil
}
