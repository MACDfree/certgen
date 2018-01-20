package ui

import (
	"net/http"
)

// StartHTTP 启动http服务
func StartHTTP(addr string) {
	http.Handle("/", http.FileServer(http.Dir("html")))
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.ListenAndServe(addr, nil)
}

// 生成证书对
func keypair(w http.ResponseWriter, r *http.Request) {

}
