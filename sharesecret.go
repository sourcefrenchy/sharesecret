package main

import (
	"bufio"
	"crypto/sha256"
	_ "crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/dchest/captcha"
	"github.com/unrolled/secure"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"text/template"
)

var (
	m             = make(map[string]string)
	noCaptchaList []string
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

// readLines reads a whole file into memory
// and returns a slice of its lines.
func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func isIpv4(in string) bool {
	_, _, err := net.ParseCIDR(in)
	if err != nil {
		fmt.Println(err)
		return false
	}
	return true
}

func generateURL(secret string) string {
	h := sha256.New()
	h.Write([]byte(secret))
	uniqueLink := hex.EncodeToString(h.Sum(nil))
	m[uniqueLink] = secret
	log.Printf("\nNew secret saved in memory fr %s", uniqueLink)
	return uniqueLink
}

func getIP(r *http.Request) (string, error) {
	//Get IP from the X-REAL-IP header
	ip := r.Header.Get("X-REAL-IP")
	netIP := net.ParseIP(ip)
	if netIP != nil {
		return ip, nil
	}

	//Get IP from X-FORWARDED-FOR header
	ips := r.Header.Get("X-FORWARDED-FOR")
	splitIps := strings.Split(ips, ",")
	for _, ip := range splitIps {
		netIP := net.ParseIP(ip)
		if netIP != nil {
			return ip, nil
		}
	}

	//Get IP from RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", err
	}
	netIP = net.ParseIP(ip)
	if netIP != nil {
		return ip, nil
	}
	return "", fmt.Errorf("No valid ip found")
}

func Find(slice []string, val string) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}
	return -1, false
}

func displaySecret(w http.ResponseWriter, filename string, u string, contextIndex bool) {
	secret := m[u]
	parsedTemplate := template.Must(template.ParseFiles(filename))
	if contextIndex {
		err := parsedTemplate.Execute(w, ContextIndex{
			Secret: secret,
		})
		_, ok := m[u]
		if ok {
			delete(m, u)
		}
		if err != nil {
			log.Println("Error executing template :", err)
			return
		}
	} else {
		err := parsedTemplate.Execute(w, ContextRoot{
			CaptchaID: captcha.New(),
			UrlID:     u,
		})
		if err != nil {
			log.Println("Error executing template :", err)
			return
		}
	}
}

func captchaHandler(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost { // GET displays captcha
		values := req.URL.Query()
		h := values["u"]

		ip, err := getIP(req)
		if err != nil {
			w.WriteHeader(400)
			w.Write([]byte("No valid ip"))
		}
		_, ipFound := Find(noCaptchaList, ip)
		if ipFound {
			log.Printf("Detected whitelisted IP address %s, skipping Captcha", ip)
			k, status := req.URL.Query()["u"]
			if !status || len(k[0]) < 1 {
				log.Println("Url Param 'u' is missing")
				return
			}
			displaySecret(w, "static/sec.html", k[0], true)
		} else {
			displaySecret(w, "static/recv.html", strings.Join(h, " "), false)
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
		displaySecret(w, "static/sec.html", req.FormValue("urlID"), true)
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

	if _, err := os.Stat("./server.crt"); os.IsNotExist(err) {
		log.Fatal("Cannot find server.crt file locally, exiting.")
	}
	if _, err := os.Stat("./server.key"); os.IsNotExist(err) {
		log.Fatal("Cannot find server.key file locally, exiting.")
	}
	if _, err := os.Stat("./networks.no.captcha"); os.IsNotExist(err) {
		log.Print("Cannot find networks.no.captcha file, captcha will apply to everyone")
	} else {
		lines, err := readLines("networks.no.captcha")
		if err != nil {
			log.Fatalf("Readlines: %s", err)
		}
		noCaptchaList = append(noCaptchaList, "::1") // insert localhost
		log.Println("> No captcha for loopback")
		for _, line := range lines {
			if isIpv4(line) {
				log.Printf("> No captcha for %s\n", line)
				noCaptchaList = append(noCaptchaList, line)
				continue
			}
		}
	}
	err := http.ListenAndServeTLS(":8888", "server.crt", "server.key", app)
	log.Fatal(err)
}
