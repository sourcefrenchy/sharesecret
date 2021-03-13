package main

import (
	"crypto/sha256"
	_ "crypto/sha256"
	"encoding/hex"
	"github.com/dchest/captcha"
	"github.com/unrolled/secure"
	"log"
	"net/http"
	"os"
	"strings"
	"text/template"
)

var (
	m = make(map[string]string)
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
	UrlID     string
}

func generateURL(secret string) string {
	h := sha256.New()
	h.Write([]byte(secret))
	uniqueLink := hex.EncodeToString(h.Sum(nil))
	m[uniqueLink] = secret
	log.Printf("\nAdding %s URL --> %s", uniqueLink, secret)
	return uniqueLink
}

func captchaHandler(w http.ResponseWriter, req *http.Request) {
	var h string

	if req.Method != http.MethodPost { // GET displays captcha
		values := req.URL.Query()
		h := values["u"]

		context := ContextRoot{
			CaptchaID: captcha.New(),
			UrlID:     strings.Join(h, " "),
		}

		parsedTemplate := template.Must(template.ParseFiles("static/recv.html"))
		err := parsedTemplate.Execute(w, context)
		if err != nil {
			log.Println("Error executing template :", err)
			return
		}
	} else { // POST if captcha works, displays secret

		if !captcha.VerifyString(req.FormValue("captchaId"), req.FormValue("captchaSolution")) { // Captcha test failed
			parsedTemplate := template.Must(template.ParseFiles("static/captchaError.html"))
			err := parsedTemplate.Execute(w, nil)
			if err != nil {
				log.Println("Error executing template :", err)
				return
			}
			return
		}

		h = req.FormValue("urlID")
		secret := m[h]
		retrieved := ContextIndex{
			Secret: secret,
		}

		_, ok := m[h]
		if ok {
			delete(m, h)
		}

		parsedTemplate := template.Must(template.ParseFiles("static/sec.html"))
		err := parsedTemplate.Execute(w, retrieved)
		if err != nil {
			log.Println("Error executing template :", err)
			return
		}

	}
}

func rootHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if req.Method != http.MethodPost {
		parsedTemplate := template.Must(template.ParseFiles("static/index.html"))
		err := parsedTemplate.Execute(w, nil)
		if err != nil {
			log.Println("Error executing template :", err)
			return
		}
	} else {

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
	mux.HandleFunc("/g", captchaHandler)
	mux.HandleFunc("/retrieve", captchaHandler)
	mux.HandleFunc("/", rootHandler)
	mux.Handle("/captcha/", captcha.Server(captcha.StdWidth, captcha.StdHeight))

	fileServer := http.FileServer(http.Dir("./static/"))
	mux.Handle("/static/", http.StripPrefix("/static", fileServer))

	log.Println("Starting server on :8888")
	app := secureMiddleware.Handler(mux)
	// err := http.ListenAndServe(":8888", app)

	if _, err := os.Stat("./server.crt"); os.IsNotExist(err) {
		log.Fatal("Cannot find server.crt file locally, exiting.")
	}
	if _, err := os.Stat("./server.key"); os.IsNotExist(err) {
		log.Fatal("Cannot find server.key file locally, exiting.")
	}
	err := http.ListenAndServeTLS(":8888", "server.crt", "server.key", app)
	log.Fatal(err)
}
