package main

import (
	"crypto/sha256"
	_ "crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/dchest/captcha"
	"github.com/unrolled/secure"
)

var (
	m           = make(map[string]string)
	ErrNotFound = errors.New("captcha: id not found")
)

const (
	// Default number of digits in captcha solution.
	DefaultLen = 6
	// The number of captchas created that triggers garbage collection used
	// by default store.
	CollectNum = 100
	// Expiration time of captchas used by default store.
	Expiration = 10 * time.Minute
	StdWidth   = 240
	StdHeight  = 80
)

// ContextIndex contains the Secret we will capture from the user
type ContextIndex struct {
	Secret string
}

// ContextResponse contains the URL we will send back to the user
type ContextResponse struct {
	URL string
}

// ContextRoot contains captcha for main page
type ContextRoot struct {
	CaptchaID string
}

func generateURL(secret string) string {
	h := sha256.New()
	h.Write([]byte(secret))
	shahash := hex.EncodeToString(h.Sum(nil))
	m[shahash] = secret
	log.Printf("\nAdding %s URL --> %s", shahash, secret)
	return shahash
}

func urlHandler(w http.ResponseWriter, req *http.Request) {
	vals := req.URL.Query()
	h, _ := vals["u"]
	log.Printf("Extracted params=%q", vals)
	log.Printf("Extracted hash=%s", h)
	secret := m[strings.Join(h, "")]
	retrieved := ContextIndex{
		Secret: secret,
	}

	_, ok := m[strings.Join(h, "")]
	if ok {
		delete(m, strings.Join(h, ""))
		log.Println("deleting from m :", h)
	}

	parsedTemplate := template.Must(template.ParseFiles("static/sec.html"))
	err := parsedTemplate.Execute(w, retrieved)
	if err != nil {
		log.Println("Error executing template :", err)
		return
	}
}

func rootHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if req.Method != http.MethodPost {

		context := ContextRoot{
			CaptchaID: captcha.New(),
		}
		log.Println("Captch ID generated :", context.CaptchaID)
		parsedTemplate := template.Must(template.ParseFiles("static/index.html"))
		err := parsedTemplate.Execute(w, context)
		if err != nil {
			log.Println("Error executing template :", err)
			return
		}
	} else {

		if !captcha.VerifyString(req.FormValue("captchaId"), req.FormValue("captchaSolution")) {
			parsedTemplate := template.Must(template.ParseFiles("static/captchaerr.html"))
			err := parsedTemplate.Execute(w, nil)
			if err != nil {
				log.Println("Error executing template :", err)
				return
			}
			return
		}

		submitted := ContextIndex{
			Secret: req.FormValue("secret"),
		}

		// output results
		context := ContextResponse{
			URL: "https://localhost:8888/g?u=" + generateURL(submitted.Secret),
		}

		parsedTemplate := template.Must(template.ParseFiles("static/url.html"))
		err := parsedTemplate.Execute(w, context)
		if err != nil {
			log.Println("Error executing template :", err)
			return
		}
	}
}

func main() {
	secureMiddleware := secure.New(secure.Options{
		// AllowedHosts:          []string{"example\\.com", ".*\\.example\\.com"},
		// AllowedHostsAreRegex:  true,
		HostsProxyHeaders: []string{"X-Forwarded-Host"},
		SSLRedirect:       true,
		SSLHost:           "localhost",
		SSLProxyHeaders:   map[string]string{"X-Forwarded-Proto": "https"},
		// STSSeconds:            31536000,
		// STSIncludeSubdomains:  true,
		// STSPreload:            true,
		FrameDeny:             true,
		ContentTypeNosniff:    true,
		BrowserXssFilter:      true,
		ContentSecurityPolicy: "script-src $NONCE",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/g", urlHandler)
	mux.HandleFunc("/", rootHandler)
	mux.Handle("/captcha/", captcha.Server(captcha.StdWidth, captcha.StdHeight))

	fileServer := http.FileServer(http.Dir("./static/"))
	mux.Handle("/static/", http.StripPrefix("/static", fileServer))

	log.Println("Starting server on :8888")
	app := secureMiddleware.Handler(mux)
	// err := http.ListenAndServe(":8888", app)
	err := http.ListenAndServeTLS(":8888", "localhost.crt", "localhost.key", app)
	log.Fatal(err)
}
