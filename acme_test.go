package acme

import (
	"fmt"
	"testing"
)

func TestACME(*testing.T) {
	a, err := NewACME("908958194@qq.com")
	if err != nil {
		fmt.Println("new error:", err)
		return
	}
	a.Obtain("app.lt53.cn")
}
