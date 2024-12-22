package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Session struct {
	conn       net.Conn
	lastActive time.Time
	buffer     []byte
	mu         sync.Mutex
}

type Server struct {
	sessions    sync.Map
	destHost    string
	destPort    string
	debug       bool
	appCommand  string
	isAppMode   bool
	allowDirect bool
	silent      bool
	redirect    string
}

func NewServer(destHost, destPort string, appCommand string, debug bool, allowDirect bool, silent bool, redirect string) *Server {
	s := &Server{
		destHost:    destHost,
		destPort:    destPort,
		debug:       debug,
		appCommand:  appCommand,
		isAppMode:   appCommand != "",
		allowDirect: allowDirect,
		silent:      silent,
		redirect:    redirect,
	}

	if s.isAppMode && s.debug && !s.silent {
		log.Printf("Starting in application mode with command: %s", appCommand)
	}

	go s.cleanupSessions()
	return s
}

func (s *Server) cleanupSessions() {
	for {
		time.Sleep(time.Minute)
		now := time.Now()
		s.sessions.Range(func(key, value interface{}) bool {
			session := value.(*Session)
			session.mu.Lock()
			if now.Sub(session.lastActive) > 5*time.Minute {
				session.conn.Close()
				s.sessions.Delete(key)
			}
			session.mu.Unlock()
			return true
		})
	}
}

func (s *Server) handleApplication(w http.ResponseWriter, r *http.Request) {
	if s.debug {
		log.Printf("Handling application request from %s", r.Header.Get("Cf-Connecting-Ip"))
	}

	parts := strings.Fields(s.appCommand)
	if len(parts) == 0 {
		http.Error(w, "Invalid application command", http.StatusInternalServerError)
		return
	}

	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Env = os.Environ()

	if s.debug {
		log.Printf("Launching application: %s", s.appCommand)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("Failed to create stdout pipe: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Printf("Failed to create stderr pipe: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := cmd.Start(); err != nil {
		log.Printf("Failed to start application: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Handle stdout in a goroutine
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if s.debug {
				log.Printf("Application stdout: %s", scanner.Text())
			}
		}
		if err := scanner.Err(); err != nil && s.debug {
			log.Printf("Error reading stdout: %v", err)
		}
	}()

	// Handle stderr in a goroutine
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			if s.debug {
				log.Printf("Application stderr: %s", scanner.Text())
			}
		}
		if err := scanner.Err(); err != nil && s.debug {
			log.Printf("Error reading stderr: %v", err)
		}
	}()

	if err := cmd.Wait(); err != nil {
		if s.debug {
			log.Printf("Application exited with error: %v", err)
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	if s.isAppMode {
		s.handleApplication(w, r)
		return
	}

	// Add basic connection logging
	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP == "" {
		clientIP = r.Header.Get("Cf-Connecting-Ip")
	}
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}

	// Get session ID early
	sessionID := r.Header.Get("X-For")
	if sessionID == "" {
		sessionID = r.Header.Get("Cf-Ray")
		if sessionID == "" {
			sessionID = r.Header.Get("Cf-Connecting-Ip")
		}
	}

	// Get and decode destination early
	encodedDest := r.Header.Get("X-Requested-With")
	if encodedDest == "" {
		redirectURL := s.redirect
		if redirectURL == "" {
			redirectURL = "https://github.com/doxx/darkflare"
		}
		log.Printf("Redirect: %s → %s", clientIP, redirectURL)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	// Check for connection termination
	if r.Header.Get("X-Connection-Close") == "true" {
		sessionDisplay := "no-session"
		if sessionID != "" {
			sessionDisplay = sessionID[:8]
		}
		log.Printf("Disconnect: %s [%s]", clientIP, sessionDisplay)
		if sessionInterface, exists := s.sessions.LoadAndDelete(sessionID); exists {
			session := sessionInterface.(*Session)
			session.conn.Close()
		}
		return
	}

	destBytes, err := base64.StdEncoding.DecodeString(encodedDest)
	if err != nil {
		http.Error(w, "Invalid destination encoding", http.StatusBadRequest)
		return
	}
	destination := string(destBytes)

	// Always log basic connection info
	sessionDisplay := "no-session"
	if sessionID != "" {
		sessionDisplay = sessionID[:8] // First 8 chars of session ID
	}
	s.logf("Connection: %s [%s] → %s", clientIP, sessionDisplay, destination)

	// Debug logging only when enabled
	if s.debug {
		log.Printf("Headers: %+v", r.Header)
		// ... rest of debug logging ...
	}

	// Verify Cloudflare connection
	cfConnecting := r.Header.Get("Cf-Connecting-Ip")
	if cfConnecting == "" && !s.allowDirect {
		http.Error(w, "Direct access not allowed", http.StatusForbidden)
		return
	}

	// Set Apache-like headers
	w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
	w.Header().Set("X-Powered-By", "PHP/7.4.33")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	// Cache control headers
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Content-Type", "application/octet-stream")

	// Validate the destination format and DNS resolution
	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		if s.debug {
			log.Printf("[DEBUG] Invalid destination format %s: %v", destination, err)
		}
		http.Error(w, fmt.Sprintf("Invalid destination format: %v", err), http.StatusBadRequest)
		return
	}

	// Additional host validation
	if host == "" {
		if s.debug {
			log.Printf("[DEBUG] Empty host in destination: %s", destination)
		}
		http.Error(w, "Empty host not allowed", http.StatusBadRequest)
		return
	}

	// Validate port
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		if s.debug {
			log.Printf("[DEBUG] Invalid port %s in destination: %v", port, err)
		}
		http.Error(w, fmt.Sprintf("Invalid port number: %s", port), http.StatusBadRequest)
		return
	}

	// DNS resolution check
	if ip := net.ParseIP(host); ip == nil {
		ips, err := net.LookupHost(host)
		if err != nil {
			if s.debug {
				log.Printf("[DEBUG] DNS resolution failed for %s: %v", host, err)
			}
			http.Error(w, fmt.Sprintf("DNS resolution failed: %v", err), http.StatusBadRequest)
			return
		}
		if len(ips) == 0 {
			if s.debug {
				log.Printf("[DEBUG] No IP addresses found for host: %s", host)
			}
			http.Error(w, "No IP addresses found for host", http.StatusBadRequest)
			return
		}
		if s.debug {
			log.Printf("[DEBUG] Resolved %s to %v", host, ips)
		}
	}

	// Validate the destination
	if !isValidDestination(destination) {
		if s.debug {
			log.Printf("[DEBUG] Invalid destination format: %s", destination)
		}
		http.Error(w, "Invalid destination", http.StatusForbidden)
		return
	}

	// Use the decoded destination for the connection
	if s.debug {
		log.Printf("[DEBUG] Connecting to %s:%s", host, port)
	}

	// Try to get session ID from various possible headers
	sessionID = r.Header.Get("X-For")
	if sessionID == "" {
		// Try Cloudflare-specific headers
		sessionID = r.Header.Get("Cf-Ray")
		if sessionID == "" {
			// Could also try other headers or generate a session ID based on IP
			sessionID = r.Header.Get("Cf-Connecting-Ip")
		}
	}

	if sessionID == "" {
		if s.debug {
			log.Printf("Error: Missing session ID from %s", r.Header.Get("Cf-Connecting-Ip"))
		}
		http.Error(w, "Missing session ID", http.StatusBadRequest)
		return
	}

	var session *Session
	sessionInterface, exists := s.sessions.Load(sessionID)
	if !exists {
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", host, port))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		session = &Session{
			conn:       conn,
			lastActive: time.Now(),
			buffer:     make([]byte, 0),
		}
		s.sessions.Store(sessionID, session)
	} else {
		session = sessionInterface.(*Session)
	}

	session.mu.Lock()
	defer session.mu.Unlock()
	session.lastActive = time.Now()

	if r.Method == http.MethodPost {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			if s.debug {
				log.Printf("Error reading request body: %v", err)
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if len(data) > 0 {
			if s.debug {
				log.Printf("POST: Writing %d bytes to connection for session %s",
					len(data),
					sessionID[:8], // First 8 chars of session ID for brevity
				)
			}
			_, err = session.conn.Write(data)
			if err != nil {
				if s.debug {
					log.Printf("Error writing to connection: %v", err)
				}
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		return
	}

	// For GET requests, read any available data
	buffer := make([]byte, 32*1024)      // 32KB buffer
	readData := make([]byte, 0, 64*1024) // 64KB initial capacity

	for {
		session.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)) // Increased from 10ms to 100ms
		n, err := session.conn.Read(buffer)
		if err != nil {
			if err != io.EOF && !err.(net.Error).Timeout() {
				if s.debug {
					log.Printf("Error reading from connection: %v", err)
				}
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			break
		}
		if n > 0 {
			readData = append(readData, buffer[:n]...)
		}
		if n < len(buffer) || len(readData) >= 64*1024 { // Added size limit check
			break
		}
	}

	// Only encode and send if we have data
	if len(readData) > 0 {
		encoded := hex.EncodeToString(readData)
		if s.debug {
			log.Printf("Response: Sending %d bytes (encoded: %d bytes) for session %s path %s",
				len(readData),
				len(encoded),
				sessionID[:8],
				r.URL.Path,
			)
		}
		w.Write([]byte(encoded))
	} else if s.debug {
		log.Printf("Response: No data to send for session %s path %s",
			sessionID[:8],
			r.URL.Path,
		)
	}
}

func main() {
	var origin string
	var certFile string
	var keyFile string
	var debug bool
	var allowDirect bool
	var appCommand string
	var silent bool
	var redirect string

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "DarkFlare Server - TCP-over-CDN tunnel server component\n")
		fmt.Fprintf(os.Stderr, "(c) 2024 Barrett Lyon\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -o        Listen address for the server\n")
		fmt.Fprintf(os.Stderr, "            Format: proto://[host]:port\n")
		fmt.Fprintf(os.Stderr, "            Default: http://0.0.0.0:8080\n\n")
		fmt.Fprintf(os.Stderr, "  -allow-direct\n")
		fmt.Fprintf(os.Stderr, "            Allow direct connections not coming through Cloudflare\n")
		fmt.Fprintf(os.Stderr, "            Default: false (only allow Cloudflare IPs)\n\n")
		fmt.Fprintf(os.Stderr, "  -c        Path to TLS certificate file\n")
		fmt.Fprintf(os.Stderr, "            Default: Auto-generated self-signed cert\n\n")
		fmt.Fprintf(os.Stderr, "  -k        Path to TLS private key file\n")
		fmt.Fprintf(os.Stderr, "            Default: Auto-generated with cert\n\n")
		fmt.Fprintf(os.Stderr, "  -debug    Enable detailed debug logging\n")
		fmt.Fprintf(os.Stderr, "            Shows connection details and errors\n\n")
		fmt.Fprintf(os.Stderr, "  -s        Silent mode\n")
		fmt.Fprintf(os.Stderr, "            Suppresses all non-error output\n\n")
		fmt.Fprintf(os.Stderr, "  -redirect Custom URL to redirect unauthorized requests\n")
		fmt.Fprintf(os.Stderr, "            Default: GitHub project page\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  Basic setup:\n")
		fmt.Fprintf(os.Stderr, "    %s -o http://0.0.0.0:8080\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  With custom TLS certificates:\n")
		fmt.Fprintf(os.Stderr, "    %s -o https://0.0.0.0:443 -c /path/to/cert.pem -k /path/to/key.pem\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Debug mode with metrics:\n")
		fmt.Fprintf(os.Stderr, "    %s -o http://0.0.0.0:8080 -debug\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Notes:\n")
		fmt.Fprintf(os.Stderr, "  - Server accepts destination from client via X-Requested-With header\n")
		fmt.Fprintf(os.Stderr, "  - Destination validation is performed for security\n")
		fmt.Fprintf(os.Stderr, "  - Use with Cloudflare as reverse proxy for best security\n\n")
		fmt.Fprintf(os.Stderr, "For more information: https://github.com/doxx/darkflare\n")
	}

	flag.StringVar(&origin, "o", "http://0.0.0.0:8080", "")
	flag.StringVar(&certFile, "c", "", "")
	flag.StringVar(&keyFile, "k", "", "")
	flag.StringVar(&appCommand, "a", "", "")
	flag.BoolVar(&debug, "debug", false, "")
	flag.BoolVar(&allowDirect, "allow-direct", false, "")
	flag.BoolVar(&silent, "s", false, "")
	flag.StringVar(&redirect, "redirect", "", "Custom URL to redirect unauthorized requests (default: GitHub project page)")
	flag.Parse()

	// Parse origin URL
	originURL, err := url.Parse(origin)
	if err != nil {
		log.Fatalf("Invalid origin URL: %v", err)
	}

	// Validate scheme
	if originURL.Scheme != "http" && originURL.Scheme != "https" {
		log.Fatal("Origin scheme must be either 'http' or 'https'")
	}

	// Validate and extract host/port
	originHost, originPort, err := net.SplitHostPort(originURL.Host)
	if err != nil {
		log.Fatalf("Invalid origin address: %v", err)
	}

	// Validate IP is local
	if !isLocalIP(originHost) {
		log.Fatal("Origin host must be a local IP address")
	}

	if !silent {
		log.Printf("DarkFlare server listening on %s", origin)
	}

	server := NewServer(originHost, originPort, appCommand, debug, allowDirect, silent, redirect)

	log.Printf("DarkFlare server running on %s://%s:%s", originURL.Scheme, originHost, originPort)
	if allowDirect {
		log.Printf("Warning: Direct connections allowed (no Cloudflare required)")
	}

	// Start server with appropriate protocol
	if originURL.Scheme == "https" {
		if certFile == "" || keyFile == "" {
			log.Fatal("HTTPS requires both certificate (-c) and key (-k) files")
		}

		// Load and verify certificates
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatalf("Failed to load certificate and key: %v", err)
		}

		server := &http.Server{
			Addr:    fmt.Sprintf("%s:%s", originHost, originPort),
			Handler: http.HandlerFunc(server.handleRequest),
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
				MaxVersion:   tls.VersionTLS13,
				// Allow any cipher suites
				CipherSuites: nil,
				// Don't verify client certs
				ClientAuth: tls.NoClientCert,
				// Handle SNI
				GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
					if debug {
						log.Printf("Client requesting certificate for server name: %s", info.ServerName)
					}
					return &cert, nil
				},
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					if debug {
						log.Printf("TLS Handshake Details:")
						log.Printf("  Client Address: %s", hello.Conn.RemoteAddr())
						log.Printf("  Server Name: %s", hello.ServerName)
						log.Printf("  Supported Versions: %v", hello.SupportedVersions)
						log.Printf("  Supported Ciphers: %v", hello.CipherSuites)
						log.Printf("  Supported Curves: %v", hello.SupportedCurves)
						log.Printf("  Supported Points: %v", hello.SupportedPoints)
						log.Printf("  ALPN Protocols: %v", hello.SupportedProtos)
					}
					return nil, nil
				},
				VerifyConnection: func(cs tls.ConnectionState) error {
					if debug {
						log.Printf("TLS Connection State:")
						log.Printf("  Version: 0x%x", cs.Version)
						log.Printf("  HandshakeComplete: %v", cs.HandshakeComplete)
						log.Printf("  CipherSuite: 0x%x", cs.CipherSuite)
						log.Printf("  NegotiatedProtocol: %s", cs.NegotiatedProtocol)
						log.Printf("  ServerName: %s", cs.ServerName)
					}
					return nil
				},
				// Enable HTTP/2 support
				NextProtos: []string{"h2", "http/1.1"},
			},
			ErrorLog: log.New(os.Stderr, "[HTTPS] ", log.LstdFlags),
			ConnState: func(conn net.Conn, state http.ConnState) {
				if debug {
					log.Printf("Connection state changed to %s from %s",
						state, conn.RemoteAddr().String())
				}
			},
		}

		log.Printf("Starting HTTPS server on %s:%s", originHost, originPort)
		if debug {
			log.Printf("TLS Configuration:")
			log.Printf("  Minimum Version: %x", server.TLSConfig.MinVersion)
			log.Printf("  Maximum Version: %x", server.TLSConfig.MaxVersion)
			log.Printf("  Certificates Loaded: %d", len(server.TLSConfig.Certificates))
			log.Printf("  Listening Address: %s", server.Addr)
			log.Printf("  Supported Protocols: %v", server.TLSConfig.NextProtos)
		}

		log.Fatal(server.ListenAndServeTLS(certFile, keyFile))
	} else {
		server := &http.Server{
			Addr:    fmt.Sprintf("%s:%s", originHost, originPort),
			Handler: http.HandlerFunc(server.handleRequest),
		}
		log.Fatal(server.ListenAndServe())
	}
}

func isLocalIP(ip string) bool {
	// Allow 0.0.0.0 as a valid binding address
	if ip == "0.0.0.0" {
		return true
	}

	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return false
	}

	// Check if it's a loopback address
	if ipAddr.IsLoopback() {
		return true
	}

	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Error getting network interfaces: %v", err)
		return false
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			log.Printf("Error getting addresses for interface %s: %v", iface.Name, err)
			continue
		}

		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if v.IP.Equal(ipAddr) {
					return true
				}
			case *net.IPAddr:
				if v.IP.Equal(ipAddr) {
					return true
				}
			}
		}
	}

	return false
}

func isValidDestination(dest string) bool {
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		return false
	}

	// Validate port
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return false
	}

	// Validate host
	if host == "" {
		return false
	}

	// Check if it's an IP address
	if ip := net.ParseIP(host); ip != nil {
		return true
	}

	// Try DNS resolution
	ips, err := net.LookupHost(host)
	return err == nil && len(ips) > 0
}

func (s *Server) logf(format string, v ...interface{}) {
	if !s.silent {
		log.Printf(format, v...)
	}
}
