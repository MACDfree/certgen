package crypto

import (
	"testing"
)

func TestJksUtil(t *testing.T) {
	err := CreateJks("www.baidu.com", []string{"test_root.crt", "test_server.crt"}, "test_server.key", "test.jks", "123456")
	if err != nil {
		t.Fatal("创建jks文件报错", err)
	}
}
