// Package ip provides IP address helpers and optional ISP detection.
// Core classification uses the Go standard library. ISP lookup is optional
// and uses the public ipinfo.io JSON API, matching the historical Onyx.Common/isp package.
package ip

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// Parse parses and trims an IP address string.
// It returns nil when the input is not a valid IP.
func Parse(ip string) net.IP {
	return net.ParseIP(strings.TrimSpace(ip))
}

// Normalize returns the canonical string form of a valid IP, or empty string
// when the input cannot be parsed.
func Normalize(ip string) string {
	parsed := Parse(ip)
	if parsed == nil {
		return ""
	}
	return parsed.String()
}

// IsValid reports whether ip is a parseable IPv4 or IPv6 address.
func IsValid(ip string) bool {
	return Parse(ip) != nil
}

// IsPublic reports whether ip is a globally routable address.
// Addresses that are private, loopback, unspecified, or link-local unicast
// are treated as non-public, matching the historical ISP detector filter.
func IsPublic(ip string) bool {
	parsed := Parse(ip)
	if parsed == nil {
		return false
	}
	return !parsed.IsPrivate() && !parsed.IsLoopback() && !parsed.IsUnspecified() && !parsed.IsLinkLocalUnicast()
}

// IsPrivateOrLocal reports whether ip is private, loopback, unspecified,
// or link-local unicast. Invalid IPs return false.
func IsPrivateOrLocal(ip string) bool {
	parsed := Parse(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsUnspecified() || parsed.IsLinkLocalUnicast()
}

// Detector resolves the internet service provider for a client IP address.
type Detector interface {
	// GetISP returns the ISP string for the given IP, or an empty string when
	// the IP is local, private, or detection fails.
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

// GetISP queries ipinfo.io for the given IP and returns its org value
// (e.g. "AS15169 Google LLC"). Errors and non-public IPs yield an empty string.
func (d *IPInfoDetector) GetISP(ip string) string {
	if !IsPublic(ip) {
		return ""
	}
	parsed := Parse(ip)

	url := fmt.Sprintf("%s/%s/json", d.baseURL, parsed.String())
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	var data ipInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return ""
	}
	return data.Org
}
