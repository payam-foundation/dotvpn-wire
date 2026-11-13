package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/payam-foundation/dotvpn-wire/auth"
	"github.com/payam-foundation/dotvpn-wire/transport"
)

func TestMirrorFallback(t *testing.T) {
	pub, priv, err := auth.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := Sign(auth.NewSigner(priv), List{
		Issued: time.Now().Unix(),
		Endpoints: []transport.Endpoint{{
			Kind: transport.KindH2,
			Name: "mirror-node",
			Addr: "192.0.2.1:443",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	jsonSigned, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	badSignature := signed
	badSignature.Sig = "invalid"

	tests := []struct {
		name       string
		status     int
		body       string
		wantSource string
		wantErr    string
	}{
		{
			name:       "encoded signed list",
			status:     http.StatusOK,
			body:       signed.Encode(),
			wantSource: "mirror",
		},
		{
			name:       "JSON signed list",
			status:     http.StatusOK,
			body:       string(jsonSigned),
			wantSource: "mirror",
		},
		{
			name:    "HTTP failure",
			status:  http.StatusServiceUnavailable,
			wantErr: "replied 503",
		},
		{
			name:    "bad signature",
			status:  http.StatusOK,
			body:    badSignature.Encode(),
			wantErr: "server list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			t.Cleanup(mirror.Close)

			client := &Client{
				Verifier: auth.NewVerifier(pub),
				Mirrors:  []string{mirror.URL},
				HTTP:     mirror.Client(),
			}
			result, refreshErr := client.Refresh(context.Background())
			if tt.wantErr != "" {
				if refreshErr == nil || !strings.Contains(refreshErr.Error(), tt.wantErr) {
					t.Fatalf("Refresh() error = %v, want containing %q", refreshErr, tt.wantErr)
				}
				if result.Source != "" {
					t.Fatalf("Refresh() source = %q, want empty", result.Source)
				}
				return
			}
			if refreshErr == nil {
				t.Fatal("Refresh() error = nil, want control fallback error")
			}
			if result.Source != tt.wantSource {
				t.Fatalf("Refresh() source = %q, want %q", result.Source, tt.wantSource)
			}
			if len(result.Endpoints) != 1 || result.Endpoints[0].Name != "mirror-node" {
				t.Fatalf("Refresh() endpoints = %#v", result.Endpoints)
			}
			if result.Signed != signed {
				t.Fatalf("Refresh() signed = %#v, want %#v", result.Signed, signed)
			}
		})
	}
}
