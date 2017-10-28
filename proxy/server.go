package main

import (
	"crypto/tls"
	"crypto/rand"
    "log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"fmt"
	"strings"
	"io"	
	"time"
	"sync"	
	"github.com/yhat/wsutil"
)

type AuthResponse struct {
	statusCode int
	redirect string
}

type Sessions struct {
	v   map[string]string
	mux sync.Mutex
}

func auth(client *http.Client, endpoint string, req *http.Request) (AuthResponse, error) {
	var authResp AuthResponse
	tokenCookie, err := req.Cookie("id_token")
	if err != nil {
		if err.Error() != "http: named cookie not present" {
			fmt.Println("id token cookie read error")
			fmt.Println("token parse error")			
			fmt.Println(err)
			return authResp, err
		}
	}
	fmt.Println("making auth request")
	authReq, err := http.NewRequest("GET", endpoint, nil)
	if tokenCookie != nil {
		authReq.Header.Add("Id_token", tokenCookie.Value)		
	}
	authReq.Header.Add("App_host", req.Host)
	authReq.Header.Add("App_referrer", req.URL.String())
	resp, err := client.Do(authReq)
	if err != nil {
		fmt.Println("auth response error")					
		fmt.Println(err)
		return authResp, err
	}
	redirect := resp.Header.Get("redirect")
	authResp = AuthResponse{ statusCode: resp.StatusCode, redirect: redirect}
	return authResp, nil
}


func isWebsocket(req *http.Request) bool {
	conn_hdr := ""
	conn_hdrs := req.Header["Connection"]
	if len(conn_hdrs) > 0 {
		conn_hdr = conn_hdrs[0]
	}

	upgrade_websocket := false
	if strings.ToLower(conn_hdr) == "upgrade" {
		upgrade_hdrs := req.Header["Upgrade"]
		if len(upgrade_hdrs) > 0 {
			upgrade_websocket = (strings.ToLower(upgrade_hdrs[0]) == "websocket")
		}
	}

	return upgrade_websocket
}

func newUUID() (string, error) {
	uuid := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, uuid)
	if n != len(uuid) || err != nil {
		return "", err
	}
	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80
	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

func isSessionValid(r *http.Request, sessions *Sessions) bool {
	sessionCookie, err := r.Cookie("App_session")
	if err != nil {
		fmt.Println("session cookie error")
		fmt.Println(err)
		return false
	}
	sessions.mux.Lock()
	defer sessions.mux.Unlock()
	if val, ok := sessions.v[sessionCookie.Value]; ok { 
		if val == sessionCookie.Value {
			return true
		} else {
			_, ok := sessions.v[val];			
			if ok {
				delete(sessions.v, val)
			}
		}
	}
	return false
}

func setSessionIfExpired(w http.ResponseWriter, r *http.Request, sessions *Sessions) {
	sessionCookieName := "App_session"
	_, err := r.Cookie(sessionCookieName)
	if err != nil {
		if err.Error() == "http: named cookie not present" { 
			sessionId, _ := newUUID()
			expiration := time.Now().Add(2 * time.Minute)			
			cookie := http.Cookie{Name: sessionCookieName,Value:sessionId, Expires:expiration }			
			http.SetCookie(w, &cookie)
			sessions.mux.Lock()
			sessions.v[sessionId] = sessionId
			sessions.mux.Unlock()
		}
	}	
}

func serveProxy(httpReverseProxy *httputil.ReverseProxy, wsReverseProxy *wsutil.ReverseProxy, w http.ResponseWriter, r *http.Request) {
	fmt.Println(r)
	fmt.Println(w)
	isWs := isWebsocket(r)
	if isWs {
		wsReverseProxy.ServeHTTP(w,r)
		return
	}
	httpReverseProxy.ServeHTTP(w,r)
}


func main() {
	tr := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    client := &http.Client{Transport: tr}	
	sessions := Sessions{ v: make(map[string]string), mux: sync.Mutex{}}
	authEndpoint := os.Getenv("AUTH_ENDPOINT")
	proxyUrl := os.Getenv("PROXY_URL")
	fmt.Println(proxyUrl)
	mux := http.NewServeMux()
	url, _ := url.Parse(proxyUrl)	
	httpReverseProxy := httputil.NewSingleHostReverseProxy(url)	
	wsReverseProxy := wsutil.NewSingleHostReverseProxy(url)
	
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		sessionValid := isSessionValid(r, &sessions)
		if sessionValid {
			fmt.Println("Session valid")
			serveProxy(httpReverseProxy, wsReverseProxy, w, r)
			return
		}

		res, err  := auth(client, authEndpoint, r)

		if err != nil { 
			http.Redirect(w, r, "/error", 302)	
			return
		}
		fmt.Println(res.statusCode)
		if res.statusCode == 200 {
			setSessionIfExpired(w, r, &sessions)
			serveProxy(httpReverseProxy, wsReverseProxy, w, r)
		} else {
			fmt.Println(res.redirect)
			http.Redirect(w, r, res.redirect, 302)	
		}

	})
	mux.HandleFunc("/unauthorized", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Unauthorized.\n"))
	})
	mux.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("Unknown Server Error.\n"))
	})
	srv := &http.Server{
        Addr:         "0.0.0.0:80",
		Handler:      mux,
	}
	log.Fatal(srv.ListenAndServe())
}