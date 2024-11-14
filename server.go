package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/armon/go-socks5"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/natefinch/lumberjack.v2"
)

type Config struct {
	Address         string   `mapstructure:"address"`
	Username        string   `mapstructure:"username"`
	Password        string   `mapstructure:"password"`
	BlockedIPs      []string `mapstructure:"blocked_ips"`
	CertFile        string   `mapstructure:"cert_file"`
	KeyFile         string   `mapstructure:"key_file"`
	EnableTLS       bool     `mapstructure:"enable_tls"`
	MaxPacketSize   int      `mapstructure:"max_packet_size"`
	CleanupInterval int      `mapstructure:"cleanup_interval"`
	SessionTimeout  int      `mapstructure:"session_timeout"`
	LogLevel        string   `mapstructure:"log_level"`
	LogFormat       string   `mapstructure:"log_format"`
}

// Definições de valores padrão
func setDefaultConfig() {
	viper.SetDefault("max_packet_size", 65535)
	viper.SetDefault("cleanup_interval", 10)
	viper.SetDefault("session_timeout", 30)
	viper.SetDefault("log_level", "info")
	viper.SetDefault("log_format", "text")
}

type UDPSession struct {
	Addr     *net.UDPAddr
	Conn     *net.UDPConn
	LastUsed time.Time
}

type UDPRelay struct {
	Sessions map[string]*UDPSession
	mu       sync.RWMutex
}

func NewUDPRelay() *UDPRelay {
	return &UDPRelay{
		Sessions: make(map[string]*UDPSession),
	}
}

func (u *UDPRelay) GetOrCreateSession(remoteAddr *net.UDPAddr, localAddr string) (*UDPSession, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	session, exists := u.Sessions[remoteAddr.String()]
	if exists {
		session.LastUsed = time.Now()
		return session, nil
	}

	conn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("falha ao criar conexão UDP: %w", err)
	}
	// Assegura que a conexão será fechada em caso de erro
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	session = &UDPSession{
		Addr:     remoteAddr,
		Conn:     conn,
		LastUsed: time.Now(),
	}
	u.Sessions[remoteAddr.String()] = session
	return session, nil
}

func (u *UDPRelay) CleanupInactiveSessions(duration time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()

	for addr, session := range u.Sessions {
		if time.Since(session.LastUsed) > duration {
			session.Conn.Close()
			delete(u.Sessions, addr)
		}
	}
}

func isUDP(packet []byte) bool {
	// Verificação mais robusta de pacotes UDP
	if len(packet) < 8 {
		return false
	}
	// Verifica se o comprimento do pacote é consistente com o cabeçalho UDP
	length := binary.BigEndian.Uint16(packet[4:6])
	return len(packet) == int(length)
}

// Substituir sync.Mutex por sync.RWMutex no cache DNS
var dnsCache = struct {
	mu    sync.RWMutex
	cache map[string]net.IP
}{
	cache: make(map[string]net.IP),
}

func resolveAddr(ctx context.Context, host string) (net.IP, error) {
	dnsCache.mu.RLock()
	if ip, found := dnsCache.cache[host]; found {
		dnsCache.mu.RUnlock()
		return ip, nil
	}
	dnsCache.mu.RUnlock()

	dnsServers := []string{"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53", "1.0.0.1:53"}
	results := make(chan net.IP, len(dnsServers))
	errors := make(chan error, len(dnsServers))

	var wg sync.WaitGroup
	for _, server := range dnsServers {
		wg.Add(1)
		go func(server string) {
			defer wg.Done()
			client := new(dns.Client)
			client.Timeout = 2 * time.Second
			msg := new(dns.Msg)
			msg.SetQuestion(dns.Fqdn(host), dns.TypeA)
			msg.RecursionDesired = true

			resp, _, err := client.Exchange(msg, server)
			if err != nil {
				errors <- err
				return
			}

			if len(resp.Answer) > 0 {
				for _, ans := range resp.Answer {
					if a, ok := ans.(*dns.A); ok {
						select {
						case results <- a.A:
						case <-ctx.Done():
						}
						return
					}
				}
			}
			errors <- fmt.Errorf("nenhuma resposta válida de %s", server)
		}(server)
	}

	go func() {
		wg.Wait()
		close(results)
		close(errors)
	}()

	select {
	case ip := <-results:
		dnsCache.mu.Lock()
		dnsCache.cache[host] = ip
		dnsCache.mu.Unlock()
		return ip, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("tempo esgotado para resolução DNS")
	}
}

func logPacket(addr net.Addr, packet []byte, logger *logrus.Logger) {
	logger.WithFields(logrus.Fields{
		"remote_addr": addr.String(),
		"packet_size": len(packet),
		"packet_data": fmt.Sprintf("%x", packet),
	}).Info("Pacote recebido")
}

func handlePacket(addr net.Addr, packet []byte, cfg Config, relay *UDPRelay, server *socks5.Server, logger *logrus.Logger) {
	if len(packet) > cfg.MaxPacketSize {
		logger.WithFields(logrus.Fields{
			"remote_addr": addr.String(),
			"packet_size": len(packet),
		}).Warn("pacote descartado por exceder o tamanho máximo permitido")
		return
	}
	// Substituir o log existente por logPacket
	logPacket(addr, packet, logger)

	if isUDP(packet) {
		udpAddr, err := net.ResolveUDPAddr("udp", addr.String())
		if err != nil {
			logger.WithFields(logrus.Fields{"error": err}).Error("erro ao resolver endereço UDP")
			return
		}

		session, err := relay.GetOrCreateSession(udpAddr, cfg.Address)
		if err != nil {
			logger.WithFields(logrus.Fields{"error": err}).Error("erro ao criar sessão UDP")
			return
		}

		logger.WithFields(logrus.Fields{
			"remote_addr": addr.String(),
			"session_addr": session.Addr.String(),
		}).Info("sessão UDP criada ou recuperada")

		_, err = session.Conn.Write(packet)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"remote_addr": addr.String(),
				"error":       err,
			}).Error("erro ao encaminhar pacote UDP")
			return
		}
	} else {
		host, port, err := net.SplitHostPort(addr.String())
		if err != nil {
			logger.WithFields(logrus.Fields{"error": err}).Error("erro ao dividir host e porta")
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ip, err := resolveAddr(ctx, host)
		if err != nil {
			logger.WithFields(logrus.Fields{"error": err}).Error("erro ao resolver endereço")
			return
		}

		tcpAddr := net.JoinHostPort(ip.String(), port)
		tcpConn, err := net.Dial("tcp", tcpAddr)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"remote_addr": addr.String(),
				"error":       err,
			}).Error("erro ao estabelecer conexão TCP")
			return
		}
		defer tcpConn.Close()

		logger.WithFields(logrus.Fields{
			"remote_addr": addr.String(),
			"tcp_addr":    tcpAddr,
		}).Info("conexão TCP estabelecida")

		_, err = tcpConn.Write(packet)
		if err != nil {
			logger.WithFields(logrus.Fields{"error": err}).Error("erro ao encaminhar pacote TCP")
			return
		}

		if err := server.ServeConn(tcpConn); err != nil && err != io.EOF {
			logger.WithFields(logrus.Fields{
				"remote_addr": addr.String(),
				"error":       err,
			}).Error("erro ao tratar conexão TCP")
		}
	}
}

func startPacketMultiplexer(cfg Config, ctx context.Context, logger *logrus.Logger, wg *sync.WaitGroup, relay *UDPRelay, server *socks5.Server) {
	defer wg.Done()

	conn, err := net.ListenPacket("udp", cfg.Address)
	if err != nil {
		logger.Fatalf("erro ao iniciar listener de pacotes: %v", err)
	}
	defer conn.Close()

	buffer := make([]byte, cfg.MaxPacketSize)
	for {
		select {
		case <-ctx.Done():
			logger.Info("encerrando listener de pacotes")
			return
		default:
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, addr, err := conn.ReadFrom(buffer)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				logger.WithFields(logrus.Fields{
					"error": err,
				}).Error("erro ao ler pacote")
				continue
			}
			if n > cfg.MaxPacketSize {
				logger.WithFields(logrus.Fields{
					"remote_addr": addr.String(),
					"packet_size": n,
				}).Warn("pacote descartado por exceder o tamanho máximo")
				continue
			}

			// Processamento paralelo de pacotes
			go handlePacket(addr, buffer[:n], cfg, relay, server, logger)
		}
	}
}

func configureLogger(cfg Config) *logrus.Logger {
	logger := logrus.New()

	switch cfg.LogFormat {
	case "json":
		logger.SetFormatter(&logrus.JSONFormatter{})
	case "text":
		logger.SetFormatter(&logrus.TextFormatter{})
	default:
		logger.SetFormatter(&logrus.TextFormatter{})
	}

	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		logger.SetLevel(logrus.InfoLevel)
	} else {
		logger.SetLevel(level)
	}

	logger.SetOutput(&lumberjack.Logger{
		Filename:   "server.log",
		MaxSize:    10,
		MaxBackups: 3,
		MaxAge:     28,
		Compress:   true,
	})

	return logger
}

func main() {
	setDefaultConfig()

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		log.Fatalf("erro ao ler o arquivo de configuração: %v", err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		log.Fatalf("erro ao processar configuração: %v", err)
	}

	// Verificação de configuração
	if cfg.Address == "" || cfg.Username == "" || cfg.Password == "" {
		log.Fatalf("configuração inválida: endereço, nome de usuário e senha são obrigatórios")
	}

	logger := configureLogger(cfg)

	logWriter := logger.Writer()
	defer logWriter.Close()
	stdLogger := log.New(logWriter, "", 0)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	credentials := socks5.StaticCredentials{cfg.Username: cfg.Password}
	auth := socks5.UserPassAuthenticator{Credentials: credentials}

	conf := &socks5.Config{
		AuthMethods: []socks5.Authenticator{auth},
		Logger:      stdLogger,
	}

	server, err := socks5.New(conf)
	if err != nil {
		logger.Fatalf("erro ao criar o servidor SOCKS5: %v", err)
	}

	var listener net.Listener
	if cfg.EnableTLS {
		logger.Info("iniciando listener TLS")
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			logger.Fatalf("erro ao carregar certificado TLS: %v", err)
		}
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
		listener, err = tls.Listen("tcp", cfg.Address, tlsConfig)
		if err != nil {
			logger.Fatalf("erro ao iniciar listener TLS: %v", err)
		}
	} else {
		logger.Info("iniciando listener TCP")
		listener, err = net.Listen("tcp", cfg.Address)
		if err != nil {
			logger.Fatalf("erro ao iniciar listener TCP: %v", err)
		}
	}

	var wg sync.WaitGroup
	relay := NewUDPRelay()

	// Limpeza periódica de sessões UDP inativas
	go func() {
		ticker := time.NewTicker(time.Duration(cfg.CleanupInterval) * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				relay.CleanupInactiveSessions(time.Duration(cfg.SessionTimeout) * time.Minute)
			case <-ctx.Done():
				return
			}
		}
	}()

	wg.Add(1)
	go startPacketMultiplexer(cfg, ctx, logger, &wg, relay, server)

	go func() {
		logger.Info("servidor SOCKS5 iniciado")
		if err := server.Serve(listener); err != nil {
			logger.Fatalf("erro ao iniciar o servidor SOCKS5: %v", err)
		}
	}()

	wg.Wait()
}
