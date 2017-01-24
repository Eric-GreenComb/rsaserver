package main

import (
	"crypto"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"github.com/gin-gonic/gin"
	"io/ioutil"
)

var DB = make(map[string]string)

func main() {
	r := gin.Default()

	// Ping test
	r.GET("/ping", func(c *gin.Context) {
		c.String(200, "pong")
	})

	r.GET("/rsa/gen/:user", func(c *gin.Context) {
		user := c.Params.ByName("user")
		RsaGenKey(1024, user)
		c.JSON(200, gin.H{"rsa": user})
	})

	r.GET("/rsa/private/:user", func(c *gin.Context) {
		user := c.Params.ByName("user")

		privateKey, err := getKey(user, "private")
		if err != nil {
			c.JSON(200, gin.H{"user": "", "key": "", "hash": ""})
			return
		}

		c.JSON(200, gin.H{"user": user, "privateKey": string(privateKey)})

	})

	r.GET("/rsa/public/:user", func(c *gin.Context) {
		user := c.Params.ByName("user")

		publicKey, err := getKey(user, "public")
		if err != nil {
			c.JSON(200, gin.H{"user": "", "addr": "", "publicKey": ""})
			return
		}

		_base64 := base64.StdEncoding.EncodeToString(publicKey)
		_addr := GenAddr(user, _base64)

		c.JSON(200, gin.H{"user": user, "addr": _addr, "publicKey": _base64})
	})

	r.GET("/rsa/sign/:user/:key", func(c *gin.Context) {
		user := c.Params.ByName("user")
		key := c.Params.ByName("key")

		publicKey, err := getKey(user, "public")
		if err != nil {
			c.JSON(200, gin.H{"user": "", "key": "", "sign": ""})
			return
		}

		signPrivateKey, err := getKey(key, "private")
		if err != nil {
			c.JSON(200, gin.H{"user": "", "key": "", "sign": ""})
			return
		}

		base64PublicKey := base64.StdEncoding.EncodeToString(publicKey)

		initData := user + base64PublicKey
		hashed := sha256.Sum256([]byte(initData))
		_sign, err := RsaSign(crypto.SHA256, hashed[:], signPrivateKey)
		if err != nil {
			c.JSON(200, gin.H{"user": "", "key": "", "sign": ""})
			return
		}

		_base64 := base64.StdEncoding.EncodeToString(_sign)

		c.JSON(200, gin.H{"user": user, "key": base64PublicKey, "sign": _base64})
	})

	r.GET("/rsa/destory/:addr/:key", func(c *gin.Context) {
		addr := c.Params.ByName("addr")
		key := c.Params.ByName("key")

		signPrivateKey, err := getKey(key, "private")
		if err != nil {
			c.JSON(200, gin.H{"addr": "", "sign": ""})
			return
		}

		hashed := sha256.Sum256([]byte(addr))
		_sign, err := RsaSign(crypto.SHA256, hashed[:], signPrivateKey)
		if err != nil {
			c.JSON(200, gin.H{"addr": "", "sign": ""})
			return
		}

		_base64 := base64.StdEncoding.EncodeToString(_sign)

		signPublicKey, err := getKey(key, "public")
		if err != nil {
			c.JSON(200, gin.H{"addr": "", "sign": ""})
			return
		}

		bVerify := RsaVerify(crypto.SHA256, hashed[:], signPublicKey, _sign)

		c.JSON(200, gin.H{"addr": addr, "sign": _base64, "verify": bVerify})
	})

	r.GET("/rsa/verify/:user", func(c *gin.Context) {

		user := c.Params.ByName("user")

		userBype := []byte(user)
		hashed := md5.Sum(userBype)

		privateKey, err := getKey(user, "private")
		if err != nil {
			c.JSON(200, gin.H{"msg": false})
			return
		}

		_sign, err := RsaSign(crypto.MD5, hashed[:], privateKey)

		publicKey, err := getKey(user, "public")
		if err != nil {
			c.JSON(200, gin.H{"msg": false})
			return
		}
		verify := RsaVerify(crypto.MD5, hashed[:], publicKey, _sign)

		c.JSON(200, gin.H{"msg": verify})

	})

	// Listen and Server in 0.0.0.0:8080
	r.Run(":3000")
}

func getKey(user, keytype string) ([]byte, error) {
	key, err := ioutil.ReadFile(user + keytype + ".pem")
	if err != nil {
		return nil, err
	}
	return key, nil
}
