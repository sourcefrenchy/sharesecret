package main

import (
	"crypto/sha256"
	_ "crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"strings"
	"text/template"

	"github.com/unrolled/secure"
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
	mux.HandleFunc("/g", urlHandler)
	mux.HandleFunc("/", rootHandler)

	fileServer := http.FileServer(http.Dir("./static/"))
	mux.Handle("/static/", http.StripPrefix("/static", fileServer))

	log.Println("Starting server on :8888")
	app := secureMiddleware.Handler(mux)
	// err := http.ListenAndServe(":8888", app)
	err := http.ListenAndServeTLS(":8888", "localhost.crt", "localhost.key", app)
	log.Fatal(err)
}
