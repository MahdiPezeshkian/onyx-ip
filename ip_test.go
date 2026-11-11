package ip_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiPezeshkian/onyx-ip"
)

func TestParseNormalizeValid(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{" 8.8.8.8 ", "8.8.8.8"},
		{"2001:db8::1", "2001:db8::1"},
		{"::1", "::1"},
	}
	for _, tc := range cases {
		if !ip.IsValid(tc.in) {
			t.Fatalf("IsValid(%q) = false", tc.in)
		}
		if got := ip.Normalize(tc.in); got != tc.want {
			t.Fatalf("Normalize(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
	if ip.IsValid("not-an-ip") || ip.Normalize("nope") != "" || ip.Parse("x") != nil {
		t.Fatal("invalid IP handling failed")
	}
}

func TestIsPublicSpecialRanges(t *testing.T) {
	nonPublic := []string{
		"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
		"::1", "0.0.0.0", "fe80::1", "fc00::1",
		"100.64.0.1",      // CGNAT
		"192.0.2.1",       // TEST-NET-1
		"198.51.100.1",    // TEST-NET-2
		"203.0.113.1",     // TEST-NET-3
		"198.18.0.1",      // benchmarking
		"224.0.0.1",       // multicast
		"255.255.255.255", // broadcast
		"2001:db8::1",     // IPv6 documentation
		"ff02::1",         // IPv6 multicast
	}
	for _, addr := range nonPublic {
		if ip.IsPublic(addr) {
			t.Fatalf("%s must not be public", addr)
		}
	}
	public := []string{"8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"}
	for _, addr := range public {
		if !ip.IsPublic(addr) {
			t.Fatalf("%s must be public", addr)
		}
	}
	if ip.IsPublic("bad") {
		t.Fatal("invalid")
	}
}

func TestIsPrivateOrLocalHistorical(t *testing.T) {
	if !ip.IsPrivateOrLocal("10.0.0.1") || ip.IsPrivateOrLocal("8.8.8.8") {
		t.Fatal("historical private/local filter")
	}
	// CGNAT is not covered by the historical helper.
	if ip.IsPrivateOrLocal("100.64.0.1") {
		t.Fatal("historical helper does not treat CGNAT as private/local")
	}
	if ip.IsPublic("100.64.0.1") {
		t.Fatal("IsPublic must reject CGNAT")
	}
}

func TestIPInfoDetector_PrivateReturnsEmpty(t *testing.T) {
	d := ip.NewIPInfoDetector(nil)
	if got := d.GetISP("127.0.0.1"); got != "" {
		t.Fatalf("private IP must yield empty ISP, got %q", got)
	}
	if got := d.GetISP("not-ip"); got != "" {
		t.Fatalf("invalid IP must yield empty ISP, got %q", got)
	}
}

func TestLookupISP_SuccessAndErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/8.8.8.8/json" {
			t.Fatalf("path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"org": "AS15169 Google LLC"})
	}))
	defer srv.Close()

	d := ip.NewIPInfoDetectorWithBaseURL(srv.Client(), srv.URL)
	org, err := d.LookupISP(context.Background(), "8.8.8.8")
	if err != nil || org != "AS15169 Google LLC" {
		t.Fatalf("LookupISP: %q %v", org, err)
	}
	if _, err := d.LookupISP(context.Background(), "10.0.0.1"); !errors.Is(err, ip.ErrNotPublic) {
		t.Fatalf("expected ErrNotPublic, got %v", err)
	}
	if _, err := d.LookupISP(context.Background(), "nope"); !errors.Is(err, ip.ErrInvalidIP) {
		t.Fatalf("expected ErrInvalidIP, got %v", err)
	}
}

func TestLookupISP_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	d := ip.NewIPInfoDetectorWithBaseURL(srv.Client(), srv.URL)
	if _, err := d.LookupISP(context.Background(), "1.1.1.1"); !errors.Is(err, ip.ErrHTTPStatus) {
		t.Fatalf("expected ErrHTTPStatus, got %v", err)
	}
	if got := d.GetISP("1.1.1.1"); got != "" {
		t.Fatalf("legacy GetISP must yield empty, got %q", got)
	}
}

func TestLookupISP_ContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := ip.NewIPInfoDetectorWithBaseURL(srv.Client(), srv.URL)
	if _, err := d.LookupISP(ctx, "8.8.8.8"); err == nil {
		t.Fatal("expected context error")
	}
}
