package auth

import (
	"encoding/base64"
	"net/http"
)

type BasicAuthHandler struct {
	username, password string
	f                  func(w http.ResponseWriter, r *http.Request)
}

func (bh *BasicAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authorization := r.Header.Get("Authorization")

	if authorization == bh.basicUserAndPass() {
		bh.f(w, r)
	} else {
		w.Header().Add("WWW-Authenticate", `Basic realm="My Server"`)
		http.Error(w, "", http.StatusUnauthorized)
	}
}

func (bh *BasicAuthHandler) basicUserAndPass() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(bh.username+":"+bh.password))
}

func BasicAuthHandleFunc(f func(w http.ResponseWriter, r *http.Request), username, password string) http.Handler {
	return &BasicAuthHandler{username, password, f}
}
