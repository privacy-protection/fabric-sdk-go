// Package fle 为字段级加密的代码，其中包含了初始化，用户密钥生成，加密和解密的方法
//
// 使用字段级进行加解密的例子如下：
//	masterKey, err := Setup(256)
//	if err != nil {
//		panic(err)
//	}
//
//	key, err := KeyGen(masterKey, []int{1, 2, 3, 4})
//	if err != nil {
//		panic(err)
//	}
//
//	data := []byte("hello world")
//	ciphertext, err := Encrypt(data, []int{2}, key.Param)
//	if err != nil {
//		panic(err)
//	}
//
//	decodedData, err := Decrypt(key, ciphertext)
//	if err != nil {
//		panic(err)
//	}
//	fmt.Println("data", string(decodedData))
package fle
