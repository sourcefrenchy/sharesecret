package main

import (
	"bufio"
	"bytes"
	_ "crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"text/template"

	"filippo.io/age"
	rl "github.com/ahmedash95/ratelimit"
	"github.com/dchest/captcha"
	log "github.com/sirupsen/logrus"
	"github.com/twinj/uuid"
	"github.com/unrolled/secure"
)

const (
	fqdn = "localhost"
	port = ":8443"
)

var (
	m              = make(map[string]string)
	noCaptchaList  []string
	rateLimitation = rl.CreateLimit("5r/s")
	mutex          sync.Mutex
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

	defer func() {
		err := file.Close()
		if err != nil {
			log.Printf("error closing file after reading: %v", err)
		}
	}()

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

func generateURL(ipaddr string, secret string) string {
	uniqueLink := uuid.NewV4().String()
	i, err := age.GenerateX25519Identity()
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	publicKey := i.Recipient()
	privateKey := i.String()
	out := &bytes.Buffer{}

	w, err := age.Encrypt(out, publicKey)
	if err != nil {
		log.Fatalf("Cannot crearw encrypted file %v", err)
	}
	if _, err := io.WriteString(w, secret); err != nil {
		log.Fatalf("Failed to write encrypted file %v", err)
	}
	if err := w.Close(); err != nil {
		log.Fatalf("Failed to close encrypted file %v", err)
	}
	log.Printf("[*] New encrypted secret from %s saved in memory at %s", ipaddr, uniqueLink)

	m[uniqueLink] = out.String()
	return uniqueLink + "." + strings.ReplaceAll(privateKey, "AGE-SECRET-KEY-", "")
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
	return "", fmt.Errorf("no valid ip found")
}

func Find(slice []string, val string) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}
	return -1, false
}

func displayGenericError(w http.ResponseWriter) {
	parsedTemplate := template.Must(template.ParseFiles("static/captchaError.html"))
	err := parsedTemplate.Execute(w, nil)
	if err != nil {
		log.Println("Error executing template :", err)
	}
}
func displaySecret(w http.ResponseWriter, filename string, url string, contextIndex bool) {
	data := strings.Split(url, ".")
	location := data[0]
	privateKey := "AGE-SECRET-KEY-" + data[1]

	_, found := m[location]
	if !found {
		log.Printf("[!] Location %s does not exist", location)
		displayGenericError(w)
		return
	}

	identity, err := age.ParseX25519Identity(privateKey)
	if err != nil {
		log.Printf("Failed to parse private key: %v", err)
		displayGenericError(w)
		return
	}
	r, err := age.Decrypt(strings.NewReader(m[location]), identity)
	if err != nil {
		log.Printf("Failed to open encrypted file: %v", err)
		displayGenericError(w)
		return
	}
	out := &bytes.Buffer{}
	if _, err := io.Copy(out, r); err != nil {
		log.Printf("Failed to read encrypted content: %v", err)
		displayGenericError(w)
		return
	}
	secret := out.String()

	parsedTemplate := template.Must(template.ParseFiles(filename))
	if contextIndex {
		err := parsedTemplate.Execute(w, ContextIndex{
			Secret: secret,
		})
		_, ok := m[location]
		if ok {
			delete(m, location)
			log.Printf("[*] Location %s decrypted and deleted", location)
		}
		if err != nil {
			log.Println("Error executing template :", err)
			return
		}
	} else {
		err := parsedTemplate.Execute(w, ContextRoot{
			CaptchaID: captcha.New(),
			UrlID:     url,
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
		// ***TODO SECURITY*** need to sanitize h, and k extracted from it
		h := values["u"]
		if len(h) > 0 {
			ip, err := getIP(req)
			if err != nil {
				w.WriteHeader(400)
				_, err := w.Write([]byte("No valid ip"))
				if err != nil {
					log.Printf("error writing to http.ResponseWriter: %v", err)
				}
			}
			_, ipFound := Find(noCaptchaList, ip+"/32")
			if ipFound {
				log.Printf("[i] Detected whitelisted IP address %s, skipping Captcha", ip)
				k, status := req.URL.Query()["u"]
				if !status || len(k[0]) < 1 {
					log.Println("Url Param 'u' is missing")
					return
				}
				displaySecret(w, "static/sec.html", k[0], true)
			} else {
				displaySecret(w, "static/recv.html", strings.Join(h, " "), false)
			}
		} else {
			displayGenericError(w)
			return
		}
	} else { // POST if captcha works, displays secret
		if !captcha.VerifyString(req.FormValue("captchaId"), req.FormValue("captchaSolution")) { // Captcha test failed
			displayGenericError(w)
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
		ip, _ := getIP(req)
		lenSecret := len(submitted.Secret)

		if lenSecret > 64 { // too long, data leakage attempt?
			var clientInfo []string
			for name, headers := range req.Header {
				name = strings.ToLower(name)
				for _, h := range headers {
					clientInfo = append(clientInfo, fmt.Sprintf("%v: %v", name, h))
				}
			}
			log.Printf("[i] New secret by %s too big (size=%d), starting with:%s... Client info: %s",
				ip, len(submitted.Secret), submitted.Secret[0:50], clientInfo)
		} else if lenSecret > 14 { // at least 15 characters nowadays...
			// output results
			context := ContextResponse{
				URL: "https://" + fqdn + port + "/g?u=" + generateURL(ip, submitted.Secret),
			}
			parsedTemplate := template.Must(template.ParseFiles("static/url.html"))
			err := parsedTemplate.Execute(w, context)
			if err != nil {
				log.Println("Error executing template :", err)
				return
			}
			return
		}
		parsedTemplate := template.Must(template.ParseFiles("static/lenerror.html"))
		err := parsedTemplate.Execute(w, nil)
		if err != nil {
			log.Println("Error executing template :", err)
			return
		}

	}
}

func main() {
	// Check if we have a white list to skip captcha and certificate files
	if _, err := os.Stat("./server.crt"); os.IsNotExist(err) {
		log.Fatal("Cannot find server.crt file locally, exiting.")
	}
	if _, err := os.Stat("./server.key"); os.IsNotExist(err) {
		log.Fatal("Cannot find server.key file locally, exiting.")
	}
	if _, err := os.Stat("./networks.no.captcha"); os.IsNotExist(err) {
		log.Print("[i] Cannot find whitelist file - captcha will apply to everyone")
	} else {
		lines, err := readLines("./networks.no.captcha")
		if err != nil {
			log.Fatalf("Cannot read file %s:", err)
		}
		for _, line := range lines {
			if isIpv4(line) {
				log.Printf("[i] No captcha for %s", line)
				noCaptchaList = append(noCaptchaList, line)
				continue
			}
		}
	}

	// Strong enough web security settings
	secureMiddleware := secure.New(secure.Options{
		HostsProxyHeaders: []string{"X-Forwarded-Host"},
		SSLRedirect:       true,
		SSLHost:           fqdn,
		SSLProxyHeaders:   map[string]string{"X-Forwarded-Proto": "https"},
		FrameDeny:          true,
		ContentTypeNosniff: true,
		BrowserXssFilter:   true,
		ContentSecurityPolicy: "default-src 'self' 'https://'" + fqdn + port + "script-src 'strict-dynamic' 'unsafe-inline' 'self' 'https://cdn.jsdelivr.net/npm/bootstrap@4.5.3/dist/js/bootstrap.bundle.min.js>' 'https://code.jquery.com/jquery-3.6.0.slim.min.js' https:;" +
			"object-src 'none'; base-uri 'none'; require-trusted-types-for 'script'",
	})
	sslCfg := &tls.Config{
		MinVersion:               tls.VersionTLS13,
		CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP521},
		PreferServerCipherSuites: true,
	}

	mux := http.NewServeMux()
	mux.Handle("/g", rateLimitationMiddleware(http.HandlerFunc(captchaHandler)))
	mux.Handle("/retrieve", rateLimitationMiddleware(http.HandlerFunc(captchaHandler)))
	mux.Handle("/", rateLimitationMiddleware(http.HandlerFunc(rootHandler)))
	mux.Handle("/captcha/", captcha.Server(captcha.StdWidth, captcha.StdHeight))

	fileServer := http.FileServer(http.Dir("./static/"))
	mux.Handle("/static/", http.StripPrefix("/static", fileServer))

	log.Printf("Starting server at https://%s%s", fqdn, port)
	app := secureMiddleware.Handler(mux)
	myHttp := &http.Server{

		Addr:         fqdn + port,
		Handler:      app,
		TLSConfig:    sslCfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	err := myHttp.ListenAndServeTLS("server.crt", "server.key")
	log.Fatal(err)
}

// rateLimitationMiddleware functions
func rateLimitationMiddleware(h http.Handler) http.Handler {
	mutex.Lock()
	defer mutex.Unlock()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _ := getIP(r) // "127.0.0.1" // use ip or any user agent here
		if !isValidRequest(rateLimitation, ip) {
			w.WriteHeader(http.StatusServiceUnavailable)
			log.Printf("[i] %s blocked: exceeding rate limit", ip)
			return
		}
		err := rateLimitation.Hit(ip)
		if err != nil {
			log.Printf("rate limit error: %v", err)
		}
		h.ServeHTTP(w, r)
	})
}

func isValidRequest(l rl.Limit, key string) bool {
	_, ok := l.Rates[key]
	if !ok {
		return true
	}
	if l.Rates[key].Hits == l.MaxRequests {
		return false
	}
	return true
}
