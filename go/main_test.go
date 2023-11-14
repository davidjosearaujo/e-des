// Copyright 2023 davidjosearaujo
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"crypto/des"
	"crypto/rand"
	"e-des/cmd"
	"testing"
	"time"

	"github.com/andreburgaud/crypt2go/ecb"
)

func TestSpeed (t *testing.T){
	var Password = "hello"
	cmd.SboxGen([]byte(Password))

	min_enc, max_enc, sum_enc := 0, 0, 0
	min_dec, max_dec, sum_dec := 0, 0, 0

	nTest := 100000

	for i := 0; i < nTest; i++ {
		message := make([]byte, 4096)
		rand.Read(message)
		
		start_enc := time.Now().Nanosecond()
		out_enc := cmd.Encrypt(message)
		delta_enc := time.Now().Nanosecond() - start_enc

		if delta_enc > max_enc {
			max_enc = delta_enc
		}
		if  delta_enc > 0 && (delta_enc < min_enc || min_enc == 0) {
			min_enc = delta_enc
		}else if delta_enc < 0{
			delta_enc = 0
		}
		sum_enc += delta_enc

		start_dec := time.Now().Nanosecond()
		out_dec := cmd.Decrypt(out_enc)
		delta_dec := time.Now().Nanosecond() - start_dec

		if delta_dec > max_dec {
			max_dec = delta_dec
		}
		if delta_dec > 0 && (delta_dec < min_dec || min_dec == 0) {
			min_dec = delta_dec
		}else if delta_dec < 0{
			delta_dec = 0
		}
		sum_dec += delta_dec

		if !bytes.Equal(out_dec, message) {
			t.Error("Decryption does not match original message!\n")
		}
	}

	t.Logf("\nEncryption times\nMax: %d\tMin: %d\tAverage: %d\n", max_enc, min_enc, sum_enc/nTest)
	t.Logf("\nDecryption times\nMax: %d\tMin: %d\tAverage: %d\n", max_dec, min_dec, sum_dec/nTest)
}

func TestSpeedDES(t *testing.T){
	key := []byte{0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC }

	min_enc, max_enc, sum_enc := 0, 0, 0
	min_dec, max_dec, sum_dec := 0, 0, 0

	nTest := 100000

	for i := 0; i < nTest; i++ {
		message := make([]byte, 4096)
		rand.Read(message)
		
		start_enc := time.Now().Nanosecond()
		out_enc, _ := DesEncryption(key, message)
		delta_enc := time.Now().Nanosecond() - start_enc

		if delta_enc > max_enc {
			max_enc = delta_enc
		}
		if delta_enc > 0 && (delta_enc < min_enc || min_enc == 0) {
			min_enc = delta_enc
		}else if delta_enc < 0{
			delta_enc = 0
		}
		sum_enc += delta_enc

		start_dec := time.Now().Nanosecond()
		out_dec, _ := DesDecryption(key, out_enc)
		delta_dec := time.Now().Nanosecond() - start_dec

		if delta_dec > max_dec {
			max_dec = delta_dec
		}
		if delta_dec > 0 && (delta_dec < min_dec || min_dec == 0) {
			min_dec = delta_dec
		}else if delta_dec < 0{
			delta_dec = 0
		}
		sum_dec += delta_dec

		if !bytes.Equal(out_dec, message) {
			t.Error("Decryption does not match original message!\n")
		}
	}

	t.Logf("\nEncryption times\nMax: %d\tMin: %d\tAverage: %d\n", max_enc, min_enc, sum_enc/nTest)
	t.Logf("\nDecryption times\nMax: %d\tMin: %d\tAverage: %d\n", max_dec, min_dec, sum_dec/nTest)
}

func DesEncryption(key, plainText []byte) ([]byte, error) {
	block, err := des.NewCipher(key)

	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	origData := PKCS5Padding(plainText, blockSize)
	blockMode := ecb.NewECBEncrypter(block)
	cryted := make([]byte, len(origData))
	blockMode.CryptBlocks(cryted, origData)
	return cryted, nil
}

func DesDecryption(key, cipherText []byte) ([]byte, error) {

	block, err := des.NewCipher(key)

	if err != nil {
		return nil, err
	}

	blockMode := ecb.NewECBDecrypter(block)
	origData := make([]byte, len(cipherText))
	blockMode.CryptBlocks(origData, cipherText)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func PKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

/*
func main() {
	originalText := make([]byte, 4096)
	rand.Read(originalText)

	key := []byte{0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC }

	cryptoText,_ := DesEncryption(key, originalText)
	decryptedText,_ := DesDecryption(key, cryptoText)
	fmt.Println(bytes.Equal(originalText,decryptedText))
}
*/