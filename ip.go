// Package ip provides IP address helpers and optional ISP detection.
//
// Classification prefers net/netip. IsPublic means a globally routable unicast
// address suitable for external ISP lookup — not merely “not RFC1918 private”.
package ip

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Sentinel errors for ISP lookup.
var (
	ErrInvalidIP  = errors.New("ip: invalid address")
	ErrNotPublic  = errors.New("ip: address is not globally public")
	ErrHTTPStatus = errors.New("ip: unexpected HTTP status from ISP provider")
	ErrEmptyOrg   = errors.New("ip: ISP provider returned an empty org")
	ErrDecode     = errors.New("ip: failed to decode ISP provider response")
)

// Parse parses and trims an IP address string.
// It returns nil when the input is not a valid IP.
func Parse(ip string) net.IP {
	return net.ParseIP(strings.TrimSpace(ip))
}

// ParseAddr parses into a netip.Addr.
func ParseAddr(ip string) (netip.Addr, error) {
	return netip.ParseAddr(strings.TrimSpace(ip))
}

// Normalize returns the canonical string form of a valid IP, or empty string
// when the input cannot be parsed.
func Normalize(ip string) string {
	addr, err := ParseAddr(ip)
	if err != nil {
		return ""
	}
	return addr.String()
}

// IsValid reports whether ip is a parseable IPv4 or IPv6 address.
func IsValid(ip string) bool {
	_, err := ParseAddr(ip)
	return err == nil
}

// nonGlobalSpecial lists IANA special-purpose ranges that are not globally
// reachable public unicast space even when IsGlobalUnicast may still be true.
// Sources: IANA IPv4/IPv6 Special-Purpose Address Registries.
var nonGlobalSpecial = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this" network
	netip.MustParsePrefix("100.64.0.0/10"),   // shared address space / CGNAT (RFC 6598)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // TEST-NET-1
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // TEST-NET-2
	netip.MustParsePrefix("203.0.113.0/24"),  // TEST-NET-3
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("2001:db8::/32"), // IPv6 documentation
	netip.MustParsePrefix("2001:10::/28"),  // ORCHID
}

// IsPublic reports whether ip is a globally routable unicast address.
//
// Policy: the address must parse, be global unicast, and must not fall into
// private, loopback, link-local, multicast, unspecified, unique-local, or the
// documented IANA special-purpose ranges above (CGNAT, TEST-NET, benchmarking,
// documentation, reserved). Invalid inputs return false.
func IsPublic(ip string) bool {
	addr, err := ParseAddr(ip)
	if err != nil {
		return false
	}
	return isPublicAddr(addr)
}

func isPublicAddr(addr netip.Addr) bool {
	if !addr.IsValid() || !addr.IsGlobalUnicast() {
		return false
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsMulticast() || addr.IsUnspecified() || addr.IsInterfaceLocalMulticast() {
		return false
	}
	// IPv6 unique local (fc00::/7) is not IsPrivate in all Go versions' helpers
	// the same way; IsPrivate covers ULA in modern Go, but keep explicit check.
	if addr.Is6() {
		if addr.IsPrivate() { // ULA
			return false
		}
	}
	for _, p := range nonGlobalSpecial {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

// IsPrivateOrLocal reports the historical filter used before expanded IsPublic:
// private, loopback, unspecified, or link-local unicast. Invalid IPs return false.
// Prefer IsPublic for global-routability decisions.
func IsPrivateOrLocal(ip string) bool {
	addr, err := ParseAddr(ip)
	if err != nil {
		return false
	}
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast()
}

// Detector resolves the internet service provider for a client IP address.
type Detector interface {
	// GetISP returns the ISP string for the given IP, or an empty string when
	// the IP is not public or detection fails. Prefer LookupISP for errors.
	GetISP(ip string) string
}

// IPInfoDetector resolves ISPs using the ipinfo.io JSON API.
type IPInfoDetector struct {
	client  *http.Client
	baseURL string
}

// NewIPInfoDetector creates an IPInfoDetector using the provided HTTP client.
// When client is nil, a default client with a 3s timeout is used.
func NewIPInfoDetector(client *http.Client) *IPInfoDetector {
	return NewIPInfoDetectorWithBaseURL(client, "https://ipinfo.io")
}

// NewIPInfoDetectorWithBaseURL creates an IPInfoDetector that queries baseURL.
// When client is nil, a default client with a 3s timeout is used.
// When baseURL is empty, https://ipinfo.io is used.
func NewIPInfoDetectorWithBaseURL(client *http.Client, baseURL string) *IPInfoDetector {
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	if baseURL == "" {
		baseURL = "https://ipinfo.io"
	}
	return &IPInfoDetector{client: client, baseURL: baseURL}
}

type ipInfoResponse struct {
	Org string `json:"org"`
}

// GetISP is the legacy convenience API. It ignores errors and returns "".
// Prefer LookupISP.
func (d *IPInfoDetector) GetISP(ip string) string {
	org, err := d.LookupISP(context.Background(), ip)
	if err != nil {
		return ""
	}
	return org
}

// LookupISP queries the configured provider with context and returns the org
// string or a typed error. It does not perform lookups for non-public IPs.
func (d *IPInfoDetector) LookupISP(ctx context.Context, ip string) (string, error) {
	addr, err := ParseAddr(ip)
	if err != nil {
		return "", ErrInvalidIP
	}
	if !isPublicAddr(addr) {
		return "", ErrNotPublic
	}

	url := fmt.Sprintf("%s/%s/json", d.baseURL, addr.String())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("%w: %d", ErrHTTPStatus, resp.StatusCode)
	}

	var data ipInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", fmt.Errorf("%w: %v", ErrDecode, err)
	}
	if strings.TrimSpace(data.Org) == "" {
		return "", ErrEmptyOrg
	}
	return data.Org, nil
}
