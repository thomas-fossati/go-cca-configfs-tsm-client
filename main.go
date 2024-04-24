package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	"github.com/google/go-configfs-tsm/report"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/veraison/apiclient/verification"
	"github.com/veraison/ear"
)

type TSMEvidenceBuilder struct{}

func (eb TSMEvidenceBuilder) BuildEvidence(nonce []byte, accept []string) ([]byte, string, error) {
	for _, ct := range accept {
		if ct == "application/eat-collection; profile=http://arm.com/CCA-SSD/1.0.0" {
			req := &report.Request{
				InBlob: nonce,
			}

			res, err := linuxtsm.GetReport(req)
			if err != nil {
				return nil, "", fmt.Errorf("GetReport failed: %s", err)
			}

			return res.OutBlob, ct, nil
		}
	}

	return nil, "", errors.New("no match on accepted media types")
}

func main() {
	cfg := verification.ChallengeResponseConfig{
		NonceSz:         64,
		EvidenceBuilder: TSMEvidenceBuilder{},
		NewSessionURI:   "http://veraison.example:8080/challenge-response/v1/newSession",
		DeleteSession:   true,
	}

	ar, err := cfg.Run()
	if err != nil {
		log.Fatalf("Veraison API client session failed: %v", err)
	}

	if err := processAR(ar[1 : len(ar)-1]); err != nil {
		log.Fatalf("EAR processing failed: %v", err)
	}
}

func processAR(ares []byte) error {
	earVerificationKey := `{
		"alg": "ES256",
		"crv": "P-256",
		"kty": "EC",
		"x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
		"y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"
	}`

	vfyK, _ := jwk.ParseKey([]byte(earVerificationKey))

	var ar ear.AttestationResult

	if err := ar.Verify(ares, jwa.ES256, vfyK); err != nil {
		return err
	}

	j, _ := ar.MarshalJSONIndent("", " ")
	fmt.Println(string(j))

	return nil
}
