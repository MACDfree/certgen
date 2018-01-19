package crypto

import (
	"testing"
)

func TestPfxUtil(t *testing.T) {
	err := CreatePfx("test_server.crt", "test_server.key", "test.pfx", "123456")

	if err != nil {
		t.Fatal("创建pfx报错", err)
	}
}
