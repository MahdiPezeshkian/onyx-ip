package ip_test

import (
	"encoding/json"
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

func TestPublicPrivateClassification(t *testing.T) {
	privates := []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "::1", "0.0.0.0", "fe80::1"}
	for _, addr := range privates {
		if ip.IsPublic(addr) {
			t.Fatalf("%s must not be public", addr)
		}
		if !ip.IsPrivateOrLocal(addr) {
			t.Fatalf("%s must be private/local", addr)
		}
	}
	if !ip.IsPublic("8.8.8.8") {
		t.Fatal("8.8.8.8 must be public")
	}
	if ip.IsPrivateOrLocal("8.8.8.8") {
		t.Fatal("8.8.8.8 must not be private/local")
	}
	if ip.IsPublic("bad") || ip.IsPrivateOrLocal("bad") {
		t.Fatal("invalid IPs must return false")
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

func TestIPInfoDetector_HTTPSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/8.8.8.8/json" {
			t.Fatalf("path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"org": "AS15169 Google LLC"})
	}))
	defer srv.Close()

	d := ip.NewIPInfoDetectorWithBaseURL(srv.Client(), srv.URL)
	if got := d.GetISP("8.8.8.8"); got != "AS15169 Google LLC" {
		t.Fatalf("GetISP: got %q", got)
	}
}

func TestIPInfoDetector_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	d := ip.NewIPInfoDetectorWithBaseURL(srv.Client(), srv.URL)
	if got := d.GetISP("1.1.1.1"); got != "" {
		t.Fatalf("non-200 must yield empty, got %q", got)
	}
}
