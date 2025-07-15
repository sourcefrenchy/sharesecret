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
	"github.com/dchest/captcha"
	log "github.com/sirupsen/logrus"
	"github.com/twinj/uuid"
	"github.com/unrolled/secure"
	"golang.org/x/time/rate"
)

var (
	fqdn = getEnv("FQDN", "localhost")
	port = getEnv("PORT", ":8443")
)

var (
	m             = make(map[string]string)
	noCaptchaList []string
	rateLimiters  = make(map[string]*rate.Limiter)
	mutex         sync.Mutex
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

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
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
	// Get IP from RemoteAddr first (most reliable)
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", err
	}
	netIP := net.ParseIP(ip)
	if netIP != nil {
		// Only trust proxy headers if coming from trusted proxy
		if isTrustedProxy(netIP) {
			// Check X-REAL-IP header
			realIP := r.Header.Get("X-REAL-IP")
			if realIP != "" {
				if parsedIP := net.ParseIP(realIP); parsedIP != nil {
					return realIP, nil
				}
			}

			// Check X-FORWARDED-FOR header (use first valid IP)
			forwardedFor := r.Header.Get("X-FORWARDED-FOR")
			if forwardedFor != "" {
				ips := strings.Split(forwardedFor, ",")
				for _, fwdIP := range ips {
					fwdIP = strings.TrimSpace(fwdIP)
					if parsedIP := net.ParseIP(fwdIP); parsedIP != nil {
						return fwdIP, nil
					}
				}
			}
		}
		return ip, nil
	}
	return "", fmt.Errorf("no valid ip found")
}

func isTrustedProxy(ip net.IP) bool {
	// Define trusted proxy networks (customize as needed)
	trustedNetworks := []string{
		"127.0.0.0/8",    // localhost
		"10.0.0.0/8",     // private networks
		"172.16.0.0/12",  // private networks
		"192.168.0.0/16", // private networks
	}

	for _, network := range trustedNetworks {
		_, cidr, err := net.ParseCIDR(network)
		if err != nil {
			continue
		}
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
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
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	parsedTemplate := template.Must(template.ParseFiles("static/captchaError.html"))
	err := parsedTemplate.Execute(w, nil)
	if err != nil {
		log.Println("Error executing template :", err)
	}
}
func displaySecret(w http.ResponseWriter, filename string, url string, contextIndex bool) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	data := strings.Split(url, ".")
	if len(data) != 2 || data[0] == "" || data[1] == "" {
		log.Printf("[!] Invalid URL format: %s", url)
		displayGenericError(w)
		return
	}
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
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
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
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
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
			userAgent := req.Header.Get("User-Agent")
			if userAgent == "" {
				userAgent = "unknown"
			}
			log.Printf("[i] New secret by %s too big (size=%d), User-Agent: %s",
				ip, len(submitted.Secret), userAgent)
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
	certFile := getEnv("TLS_CERT_FILE", "./server.crt")
	keyFile := getEnv("TLS_KEY_FILE", "./server.key")

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Fatalf("Cannot find certificate file %s, exiting.", certFile)
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Fatalf("Cannot find key file %s, exiting.", keyFile)
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
		HostsProxyHeaders:       []string{"X-Forwarded-Host"},
		SSLRedirect:             true,
		SSLHost:                 fqdn,
		SSLProxyHeaders:         map[string]string{"X-Forwarded-Proto": "https"},
		STSSeconds:              31536000,
		STSIncludeSubdomains:    true,
		STSPreload:              true,
		FrameDeny:               true,
		ContentTypeNosniff:      true,
		BrowserXssFilter:        true,
		ReferrerPolicy:          "strict-origin-when-cross-origin",
		ContentSecurityPolicy:   "default-src 'self'; script-src 'self' 'unsafe-inline' https://code.jquery.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
		CustomFrameOptionsValue: "DENY",
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
	err := myHttp.ListenAndServeTLS(certFile, keyFile)
	log.Fatal(err)
}

// rateLimitationMiddleware functions
func rateLimitationMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _ := getIP(r) // "127.0.0.1" // use ip or any user agent here

		mutex.Lock()
		limiter, exists := rateLimiters[ip]
		if !exists {
			// Create new limiter: 5 requests per second with burst of 5
			limiter = rate.NewLimiter(rate.Limit(5), 5)
			rateLimiters[ip] = limiter
		}
		mutex.Unlock()

		if !limiter.Allow() {
			w.WriteHeader(http.StatusServiceUnavailable)
			log.Printf("[i] %s blocked: exceeding rate limit", ip)
			return
		}
		h.ServeHTTP(w, r)
	})
}
