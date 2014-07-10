package auth

import (
	"encoding/base64"
	"net/http"
	"net/url"
)

type BasicAuthHandler struct {
	f        func(w http.ResponseWriter, r *http.Request)
	userinfo *url.Userinfo
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
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(bh.userinfo.String()))
}

func BasicAuthHandleFunc(f func(w http.ResponseWriter, r *http.Request), userinfo *url.Userinfo) http.Handler {
	return &BasicAuthHandler{f, userinfo}
}
