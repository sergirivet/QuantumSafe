package discovery

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidTarget    = errors.New("invalid target")
	ErrTargetNotAllowed = errors.New("target is not allowed")
)

type Resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type Scanner interface {
	Scan(context.Context, string) (Report, error)
}

type Engine struct {
	resolver       Resolver
	dialer         Dialer
	timeout        time.Duration
	maxConcurrency int
	maxAddresses   int
	ports          []int
}

type Options struct {
	Timeout        time.Duration
	MaxConcurrency int
	MaxAddresses   int
	Ports          []int
}

type Report struct {
	SchemaVersion      int       `json:"schema_version"`
	Target             string    `json:"target"`
	ScannedAt          time.Time `json:"scanned_at"`
	DurationMS         int64     `json:"duration_ms"`
	Addresses          []Address `json:"addresses"`
	AddressesTruncated bool      `json:"addresses_truncated,omitempty"`
	Services           []Service `json:"services"`
}

type Address struct {
	IP string `json:"ip"`
}

type Service struct {
	IP       string           `json:"ip"`
	Port     int              `json:"port"`
	Protocol string           `json:"protocol"`
	HTTP     *HTTPObservation `json:"http,omitempty"`
	TLS      *TLSObservation  `json:"tls,omitempty"`
}

type HTTPObservation struct {
	StatusCode int    `json:"status_code"`
	URL        string `json:"url"`
}

type TLSObservation struct {
	FingerprintSHA256  string    `json:"fingerprint_sha256,omitempty"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm,omitempty"`
	Version            string    `json:"version"`
	CipherSuite        string    `json:"cipher_suite"`
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	DNSNames           []string  `json:"dns_names,omitempty"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	CertificateExpired bool      `json:"certificate_expired"`
}

func New() *Engine {
	return NewWithOptions(DefaultOptions())
}

func DefaultOptions() Options {
	return Options{
		Timeout:        5 * time.Second,
		MaxConcurrency: 8,
		MaxAddresses:   32,
		Ports:          []int{80, 443},
	}
}

func NewWithOptions(options Options) *Engine {
	defaults := DefaultOptions()
	if options.Timeout <= 0 {
		options.Timeout = defaults.Timeout
	}
	if options.MaxConcurrency <= 0 {
		options.MaxConcurrency = defaults.MaxConcurrency
	}
	if options.MaxAddresses <= 0 {
		options.MaxAddresses = defaults.MaxAddresses
	}
	if len(options.Ports) == 0 {
		options.Ports = defaults.Ports
	}

	return &Engine{
		resolver:       net.DefaultResolver,
		dialer:         &net.Dialer{Timeout: options.Timeout},
		timeout:        options.Timeout,
		maxConcurrency: options.MaxConcurrency,
		maxAddresses:   options.MaxAddresses,
		ports:          append([]int(nil), options.Ports...),
	}
}

func (e *Engine) Scan(ctx context.Context, rawTarget string) (Report, error) {
	started := time.Now()
	target, err := normalizeTarget(rawTarget)
	if err != nil {
		return Report{}, err
	}

	addresses, err := e.resolver.LookupIPAddr(ctx, target)
	if err != nil {
		return Report{}, fmt.Errorf("resolve target %q: %w", target, err)
	}

	publicIPs := uniquePublicIPs(addresses)
	if len(publicIPs) == 0 {
		return Report{}, fmt.Errorf("%w: %s", ErrTargetNotAllowed, target)
	}
	maxAddresses := e.maxAddresses
	if maxAddresses <= 0 {
		maxAddresses = len(publicIPs)
	}
	addressesTruncated := len(publicIPs) > maxAddresses
	if addressesTruncated {
		publicIPs = publicIPs[:maxAddresses]
	}

	report := Report{
		SchemaVersion:      1,
		Target:             target,
		ScannedAt:          started.UTC(),
		AddressesTruncated: addressesTruncated,
		Addresses:          make([]Address, 0, len(publicIPs)),
		Services:           make([]Service, 0),
	}
	for _, ip := range publicIPs {
		report.Addresses = append(report.Addresses, Address{IP: ip.String()})
	}

	services, err := e.scanServices(ctx, target, publicIPs)
	if err != nil {
		return Report{}, err
	}
	report.Services = services
	report.DurationMS = time.Since(started).Milliseconds()
	return report, nil
}

func (e *Engine) scanServices(ctx context.Context, target string, ips []net.IP) ([]Service, error) {
	type job struct {
		ip   net.IP
		port int
	}

	ports := e.ports
	if len(ports) == 0 {
		ports = DefaultOptions().Ports
	}
	jobs := make(chan job)
	results := make(chan Service, len(ips)*2)
	var workers sync.WaitGroup
	workerCount := e.maxConcurrency
	if workerCount < 1 {
		workerCount = 1
	}
	if workerCount > len(ips)*2 {
		workerCount = len(ips) * 2
	}

	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for current := range jobs {
				service, reachable := e.probeService(ctx, target, current.ip, current.port)
				if reachable {
					results <- service
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, ip := range ips {
			for _, port := range ports {
				select {
				case jobs <- job{ip: ip, port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	workers.Wait()
	close(results)
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("scan services: %w", err)
	}

	services := make([]Service, 0, len(results))
	for service := range results {
		services = append(services, service)
	}
	sort.Slice(services, func(left, right int) bool {
		if services[left].IP == services[right].IP {
			return services[left].Port < services[right].Port
		}
		return services[left].IP < services[right].IP
	})
	return services, nil
}

func (e *Engine) probeService(ctx context.Context, target string, ip net.IP, port int) (Service, bool) {
	probeContext, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	address := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	connection, err := e.dialer.DialContext(probeContext, "tcp", address)
	if err != nil {
		return Service{}, false
	}
	_ = connection.Close()

	service := Service{IP: ip.String(), Port: port, Protocol: "tcp"}
	if port == 80 {
		service.Protocol = "http"
		service.HTTP = e.probeHTTP(probeContext, target, ip, port, false)
	}
	if port == 443 {
		service.Protocol = "https"
		service.TLS = e.probeTLS(probeContext, target, ip, port)
		service.HTTP = e.probeHTTP(probeContext, target, ip, port, true)
	}
	return service, true
}

func (e *Engine) probeHTTP(ctx context.Context, target string, ip net.IP, port int, secure bool) *HTTPObservation {
	scheme := "http"
	if secure {
		scheme = "https"
	}

	transport := &http.Transport{
		DialContext: func(dialContext context.Context, network, _ string) (net.Conn, error) {
			return e.dialer.DialContext(dialContext, network, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		},
	}
	if secure {
		transport.TLSClientConfig = &tls.Config{ServerName: target, MinVersion: tls.VersionTLS12}
	}
	defer transport.CloseIdleConnections()

	request, err := http.NewRequestWithContext(ctx, http.MethodHead, scheme+"://"+target, nil)
	if err != nil {
		return nil
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   e.timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		return nil
	}
	defer response.Body.Close()

	return &HTTPObservation{StatusCode: response.StatusCode, URL: response.Request.URL.String()}
}

func (e *Engine) probeTLS(ctx context.Context, target string, ip net.IP, port int) *TLSObservation {
	address := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	connection, err := e.dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil
	}
	defer connection.Close()

	tlsConnection := tls.Client(connection, &tls.Config{ServerName: target, MinVersion: tls.VersionTLS12})
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return nil
	}
	return tlsObservation(tlsConnection.ConnectionState())
}

func tlsObservation(state tls.ConnectionState) *TLSObservation {
	observation := &TLSObservation{
		Version:     tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
	}
	if len(state.PeerCertificates) == 0 {
		return observation
	}

	certificate := state.PeerCertificates[0]
	digest := sha256.Sum256(certificate.Raw)
	observation.Subject = certificate.Subject.String()
	observation.FingerprintSHA256 = fmt.Sprintf("%x", digest[:])
	if certificate.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		observation.PublicKeyAlgorithm = certificate.PublicKeyAlgorithm.String()
	}
	observation.Issuer = certificate.Issuer.String()
	observation.DNSNames = append([]string(nil), certificate.DNSNames...)
	observation.NotBefore = certificate.NotBefore
	observation.NotAfter = certificate.NotAfter
	observation.CertificateExpired = time.Now().UTC().After(certificate.NotAfter)
	return observation
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}

func normalizeTarget(rawTarget string) (string, error) {
	target := strings.TrimSpace(strings.TrimSuffix(rawTarget, "."))
	if target == "" || len(target) > 253 {
		return "", fmt.Errorf("%w: %q", ErrInvalidTarget, rawTarget)
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%w: use a hostname without a URL scheme or path", ErrInvalidTarget)
	}
	if net.ParseIP(target) != nil || strings.Contains(target, ":") || strings.ContainsAny(target, "@/\\") {
		return "", fmt.Errorf("%w: hostname required", ErrInvalidTarget)
	}

	for _, label := range strings.Split(target, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("%w: invalid hostname label", ErrInvalidTarget)
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' {
				return "", fmt.Errorf("%w: invalid hostname character", ErrInvalidTarget)
			}
		}
	}
	return strings.ToLower(target), nil
}

func uniquePublicIPs(addresses []net.IPAddr) []net.IP {
	seen := make(map[string]struct{}, len(addresses))
	publicIPs := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		if !isPublicIP(address.IP) {
			continue
		}
		key := address.IP.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		publicIPs = append(publicIPs, address.IP)
	}
	sort.Slice(publicIPs, func(left, right int) bool {
		return publicIPs[left].String() < publicIPs[right].String()
	})
	return publicIPs
}

func isPublicIP(ip net.IP) bool {
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}

	ipv4 := ip.To4()
	if ipv4 != nil && ipv4[0] == 100 && ipv4[1] >= 64 && ipv4[1] <= 127 {
		return false
	}
	return true
}
