package jwt_sm4

import (
	"bytes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tjfoc/gmsm/sm4"

	"local/global"

	"github.com/rs/zerolog/log"
)

type Instance struct {
	Expires int64  `json:"expires,omitempty"`
	Key     string `json:"key"`
	IV      string `json:"iv,omitempty"`
}

type _Claims struct {
	Expires   int64  `json:"expires,omitempty"`
	Aud       string `json:"aud,omitempty"`
	IP        string `json:"ip,omitempty"`
	TokenHash string `json:"token_hash,omitempty"`
}

func New(config string) (*Instance, error) {
	var instance Instance
	err := json.Unmarshal(global.StrToBytes(config), &instance)
	if err != nil {
		return nil, err
	}
	if len(instance.Key) != 16 {
		return nil, errors.New("private_key的长度必须是16个字符")
	}
	if instance.IV == "" {
		instance.IV = instance.Key
	} else if len(instance.IV) != 16 {
		instance.IV = paddingIV(instance.IV)
	}
	return &instance, err
}
func (receiver *Instance) Sign(tokenHash string) (tokenStr string, err error) {
	var (
		claims      _Claims
		header      string
		claimsBytes []byte
		token       strings.Builder
		signBytes   []byte
	)
	if receiver.Expires > 0 {
		claims.Expires = time.Now().Add(time.Duration(receiver.Expires) * time.Second).Unix()
	}
	// header部份
	header = `{"alg":"SM4","typ":"JWT"}`
	// payload部份
	claimsBytes, err = json.Marshal(&claims)
	if err != nil {
		log.Err(err).Caller().Send()
		return
	}
	token.WriteString(base64.RawURLEncoding.EncodeToString(global.StrToBytes(header)))
	token.WriteString(".")
	token.WriteString(base64.RawURLEncoding.EncodeToString(claimsBytes))

	// 签名
	signBytes, err = sm4Encrypt(global.StrToBytes(receiver.Key), global.StrToBytes(receiver.IV), global.StrToBytes(token.String()))
	if err != nil {
		log.Err(err).Caller().Send()
		return "", err
	}

	token.WriteString(".")
	token.WriteString(base64.RawURLEncoding.EncodeToString(signBytes))
	tokenStr = token.String()
	return
}

func (receiver *Instance) VeritySign(tokenStr string) (global.UpdaterClaims, bool) {
	var claims global.UpdaterClaims
	jwtClaims, err := parseClaims(receiver.Key, receiver.IV, tokenStr)
	if err != nil {
		return claims, false
	}
	claims.Expires = jwtClaims.Expires
	claims.TokenHash = jwtClaims.TokenHash
	claims.Aud = jwtClaims.Aud
	claims.IP = jwtClaims.IP
	return claims, true
}

func parseClaims(key string, iv string, tokenStr string) (claims _Claims, err error) {
	var claimsBytes, signBytes, plainTextBytes []byte
	arr := strings.Split(tokenStr, ".")
	if len(arr) != 3 {
		err = errors.New("token无效")
		log.Err(err).Caller().Send()
		return
	}
	claimsBytes, err = base64.RawURLEncoding.DecodeString(arr[1])
	if err != nil {
		log.Err(err).Caller().Send()
		return
	}
	signBytes, err = base64.RawURLEncoding.DecodeString(arr[2])
	if err != nil {
		return
	}
	// 加密前的明文[base64(header).base64(claims)]
	msg := arr[0] + "." + arr[1]
	// 使用key解密签名部分
	plainTextBytes, err = sm4Decrypt(global.StrToBytes(key), global.StrToBytes(iv), signBytes)
	if err != nil {
		err = errors.New("签名无效")
		return
	}
	// 比较解密后的明文是否等于[header.claims]
	if global.BytesToStr(plainTextBytes) != msg {
		err = errors.New("签名无效")
		return
	}
	// 解析claims
	if err = json.Unmarshal(claimsBytes, &claims); err != nil {
		log.Err(err).Caller().Send()
		return
	}
	return
}

func paddingIV(iv string) string {
	pandding := fmt.Sprintf("%016s", "")
	return fmt.Sprintf("%.16s", iv+pandding)
}

func sm4Encrypt(key, iv, plainText []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData := pkcs5Padding(plainText, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cryted := make([]byte, len(origData))
	blockMode.CryptBlocks(cryted, origData)
	return cryted, nil
}

func sm4Decrypt(key, iv, cipherText []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(cipherText))
	blockMode.CryptBlocks(origData, cipherText)
	origData = pkcs5UnPadding(origData)
	return origData, nil
}

// pkcs5填充
func pkcs5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func pkcs5UnPadding(src []byte) []byte {
	length := len(src)
	if length == 0 {
		return nil
	}
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}
