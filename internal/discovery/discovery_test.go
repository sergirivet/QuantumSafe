package discovery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNormalizeTargetRejectsURL(t *testing.T) {
	_, err := normalizeTarget("https://example.com/path")
	if !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("expected invalid target error, got %v", err)
	}
}

func TestScanRejectsPrivateResolution(t *testing.T) {
	engine := &Engine{
		resolver: fakeResolver{addresses: []net.IPAddr{{IP: net.ParseIP("10.0.0.1")}}},
		timeout:  time.Second,
	}

	_, err := engine.Scan(context.Background(), "internal.example")
	if !errors.Is(err, ErrTargetNotAllowed) {
		t.Fatalf("expected target not allowed error, got %v", err)
	}
}

func TestScanPropagatesResolverError(t *testing.T) {
	resolverError := errors.New("resolver unavailable")
	engine := &Engine{
		resolver: fakeResolver{err: resolverError},
		timeout:  time.Second,
	}

	_, err := engine.Scan(context.Background(), "example.com")
	if !errors.Is(err, resolverError) {
		t.Fatalf("expected resolver error, got %v", err)
	}
}

func TestScanPropagatesContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	engine := &Engine{
		resolver: fakeResolver{err: context.Canceled},
		timeout:  time.Second,
	}

	_, err := engine.Scan(ctx, "example.com")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}
}

func TestTLSObservationParsesConnectionState(t *testing.T) {
	notBefore := time.Now().UTC().Add(-time.Hour)
	notAfter := time.Now().UTC().Add(time.Hour)
	certificate := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "example.com"},
		Issuer:    pkix.Name{CommonName: "Example CA"},
		DNSNames:  []string{"example.com", "www.example.com"},
		NotBefore: notBefore,
		NotAfter:  notAfter,
	}

	observation := tlsObservation(tls.ConnectionState{
		Version:          tls.VersionTLS13,
		CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates: []*x509.Certificate{certificate},
	})

	if observation.Version != "TLS 1.3" {
		t.Fatalf("unexpected TLS version: %q", observation.Version)
	}
	if observation.CipherSuite != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("unexpected cipher suite: %q", observation.CipherSuite)
	}
	if !strings.Contains(observation.Subject, "example.com") || observation.CertificateExpired {
		t.Fatalf("unexpected certificate observation: %+v", observation)
	}
	if len(observation.DNSNames) != 2 {
		t.Fatalf("expected two DNS names, got %d", len(observation.DNSNames))
	}
}

func TestScanLimitsResolvedAddresses(t *testing.T) {
	engine := &Engine{
		resolver: fakeResolver{addresses: []net.IPAddr{
			{IP: net.ParseIP("203.0.113.10")},
			{IP: net.ParseIP("198.51.100.20")},
		}},
		dialer:       rejectingDialer{},
		timeout:      time.Second,
		maxAddresses: 1,
		ports:        []int{443},
	}

	report, err := engine.Scan(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("expected successful bounded scan, got %v", err)
	}
	if len(report.Addresses) != 1 || !report.AddressesTruncated {
		t.Fatalf("unexpected bounded report: %+v", report)
	}
}

type fakeResolver struct {
	addresses []net.IPAddr
	err       error
}

func (resolver fakeResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return resolver.addresses, resolver.err
}

type rejectingDialer struct{}

func (rejectingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("connection rejected")
}
