package fiskalhrgo

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
)

func TestGetCertOIB(t *testing.T) {
	tests := []struct {
		name         string
		organization string
		country      string
		expectedOIB  string
		expectAnyErr bool
		expectedErr  error
	}{
		{
			name:         "extracts OIB from HR94995863109",
			organization: "HR94995863109",
			country:      "HR",
			expectedOIB:  "94995863109",
		},
		{
			name:         "extracts OIB from HR26875850100",
			organization: "abc HR26875850100 efg",
			country:      "HR",
			expectedOIB:  "26875850100",
		},
		{
			name:         "fails when country code prefix does not match",
			organization: "XX94995863109",
			country:      "HR",
			expectAnyErr: true,
		},
		{
			name:         "fails when extracted numeric part is invalid",
			organization: "HR12345678901",
			country:      "HR",
			expectedErr:  ErrOIBInvalid,
		},
		{
			name: "ok",
			organization: `CN = FISKAL 1
L = PILJENICE
2.5.4.97 = HR00000000010
O = GRAĐEVINSKI OBRT KARMELA
C = HR`,
			country:     "HR",
			expectedOIB: "00000000010",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cm := &certManager{
				publicCert: &x509.Certificate{
					Subject: pkix.Name{
						Organization: []string{tc.organization},
						Country:      []string{tc.country},
					},
				},
			}

			oib, err := cm.getCertOIB()
			if tc.expectAnyErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}

			if tc.expectedErr != nil {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !errors.Is(err, tc.expectedErr) {
					t.Fatalf("expected error %v, got %v", tc.expectedErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if oib != tc.expectedOIB {
				t.Fatalf("expected OIB %s, got %s", tc.expectedOIB, oib)
			}
		})
	}
}
