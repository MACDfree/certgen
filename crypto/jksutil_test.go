package crypto

import (
	"testing"
)

func TestJksUtil(t *testing.T) {
	CreateJks("www.baidu.com", []string{"test_root.crt", "test_server.crt"}, "test_server.key", "test.jks", "123456")
}
