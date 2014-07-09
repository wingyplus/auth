package auth

import (
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPassBasicAuthentication(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello Success Authentication"))
	}
	ts := httptest.NewServer(BasicAuthHandleFunc(handler, "Username", "Password"))
	defer ts.Close()

	request, err := http.NewRequest("GET", ts.URL, nil)

	assertError(t, err)

	request.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("Username:Password")))

	client := &http.Client{}
	response, err := client.Do(request)

	assertError(t, err)

	if response.StatusCode != http.StatusOK {
		t.Errorf("expect status OK but was %s", response.Status)
	}

	body, err := ioutil.ReadAll(response.Body)

	assertError(t, err)

	if string(body) != "Hello Success Authentication" {
		t.Errorf("expect %s but was %s", "Hello Success Authentication", string(body))
	}
}

func TestFailBasicAuthentication(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello Fail Authentication"))
	}
	ts := httptest.NewServer(BasicAuthHandleFunc(handler, "Username", "Password"))
	defer ts.Close()

	request, err := http.NewRequest("GET", ts.URL, nil)

	assertError(t, err)

	request.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("Username:WrongPassword")))

	client := &http.Client{}
	response, err := client.Do(request)

	assertError(t, err)

	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("expect status Unauthorized but was %s", response.Status)
	}

	if response.Header.Get("WWW-Authenticate") != `Basic realm="My Server"` {
		t.Errorf("expect WWW-Authenticate value but was %s", response.Header.Get("WWW-Authenticate"))
	}
}

func assertError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("expect not nil but was %s", err.Error())
	}
}
