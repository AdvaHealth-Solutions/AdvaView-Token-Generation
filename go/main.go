// Example: generating an AdvaView launch token in Go.
//
// An AdvaView launch token is a short-lived credential that grants a named user access to a
// specific set of studies in AdvaView, the AdvaPACS viewer. Your system builds the token, protects
// it with the access key you were issued, and passes it to AdvaView.
//
// How a launch token is produced:
//  1. Collect the inputs   - who the user is, which studies they may open, and the token lifetime.
//  2. Build the payload    - the JSON claims AdvaView will read.
//  3. Protect the payload  - encrypt it (JWE, recommended) or sign it (JWS) using your access key.
//
// Uses the go-jose library (https://github.com/go-jose/go-jose).
//
// Usage:
//
//	go run . --username jane.doe@example.com --suid 1.2.840.113619.2.55.3.1234 \
//	    --accessKeyId <id> --accessKeySecret <secret> --expireAfter 300
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// ---------------------------------------------------------------------------------------------
// Step 1: collect the inputs.
//
// In your own integration these values would come from your application: the signed-in user, the
// studies they are viewing, and the access key stored in your secrets manager.
// ---------------------------------------------------------------------------------------------

type inputs struct {
	username        string
	suids           []string
	patientID       string
	accNums         []string
	mode            string
	accessKeyID     string
	accessKeySecret string
	expireAfter     int64
}

// repeatable lets a flag be given more than once (e.g. --suid a --suid b).
type repeatable []string

func (r *repeatable) String() string     { return strings.Join(*r, ",") }
func (r *repeatable) Set(v string) error { *r = append(*r, v); return nil }

func readInputs() (*inputs, error) {
	in := &inputs{}
	var suids, accNums repeatable

	flag.StringVar(&in.username, "username", "", "the user the token is issued to (required)")
	flag.Var(&suids, "suid", "Study Instance UID (repeatable)")
	flag.StringVar(&in.patientID, "patientId", "", "patient ID, used with --accNum")
	flag.Var(&accNums, "accNum", "accession number (repeatable)")
	flag.StringVar(&in.mode, "mode", "jwe", "jwe | jws | json (JWE is the recommended default)")
	flag.StringVar(&in.accessKeyID, "accessKeyId", "", "access key ID (required unless --mode json)")
	flag.StringVar(&in.accessKeySecret, "accessKeySecret", "", "access key secret (required unless --mode json)")
	flag.Int64Var(&in.expireAfter, "expireAfter", 0, "token lifetime in seconds (required)")
	flag.Parse()

	in.suids, in.accNums = suids, accNums
	in.mode = strings.ToLower(in.mode)

	if in.username == "" {
		return nil, errors.New("--username is required")
	}
	if in.expireAfter <= 0 {
		return nil, errors.New("--expireAfter is required and must be a positive number of seconds")
	}

	// Studies are identified EITHER by Study Instance UID, OR by patient ID + accession number(s).
	bySuid := len(in.suids) > 0
	byAccession := in.patientID != "" && len(in.accNums) > 0
	if bySuid == byAccession {
		return nil, errors.New("provide either at least one --suid, OR --patientId with at least one --accNum (not both)")
	}

	switch in.mode {
	case "json":
	case "jwe", "jws":
		if in.accessKeyID == "" || in.accessKeySecret == "" {
			return nil, errors.New("--accessKeyId and --accessKeySecret are required unless --mode is json")
		}
	default:
		return nil, errors.New("--mode must be jwe, jws or json")
	}

	return in, nil
}

// ---------------------------------------------------------------------------------------------
// Step 2: build the JSON payload (the token's claims).
// ---------------------------------------------------------------------------------------------

// Study identifies one study, by EITHER its Study Instance UID OR its accession number.
type Study struct {
	StudyInstanceUID string `json:"studyInstanceUid,omitempty"`
	AccessionNumber  string `json:"accessionNumber,omitempty"`
}

// Payload is the set of claims carried inside the token.
type Payload struct {
	// The user the token is issued to.
	Username string `json:"username"`
	// Only present when studies are identified by accession number.
	PatientID string `json:"patientId,omitempty"`
	// The studies the user may open.
	Studies []Study `json:"studies"`
	// When the token stops being accepted, in seconds since the Unix epoch (UTC).
	ExpiresAt int64 `json:"expiresAt"`
	// A unique ID for this token. Generate a new random value for every token; it lets AdvaPACS
	// reject a token that is presented more than once.
	JTI string `json:"jti"`
}

func buildPayload(in *inputs) ([]byte, error) {
	p := Payload{Username: in.username}

	if len(in.suids) > 0 {
		for _, uid := range in.suids {
			p.Studies = append(p.Studies, Study{StudyInstanceUID: uid})
		}
	} else {
		p.PatientID = in.patientID
		for _, acc := range in.accNums {
			p.Studies = append(p.Studies, Study{AccessionNumber: acc})
		}
	}

	p.ExpiresAt = time.Now().Add(time.Duration(in.expireAfter) * time.Second).Unix()
	p.JTI = newUUID()

	return json.Marshal(p)
}

// newUUID returns a random (version 4) UUID.
func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ---------------------------------------------------------------------------------------------
// Step 3: protect the payload with your access key.
//
//	Key derivation: the 256-bit key is SHA-256(UTF-8 bytes of the access key secret).
//	                Use the hash, not the raw secret.
//	Key ID:         the access key ID goes in the `kid` header so AdvaPACS knows which key to use.
//	JWE (recommended): alg A256KW, enc A256GCM. The payload is encrypted, so patient
//	                   identifiers (PHI) can't leak into server logs, proxies or browser
//	                   history, and it can't be altered.
//	JWS:               alg HS256. Tamper-proof, but the payload is only base64url-encoded,
//	                   so anyone who sees the token can read it. Use only if you can't use JWE.
// ---------------------------------------------------------------------------------------------

func deriveKey(accessKeySecret string) []byte {
	sum := sha256.Sum256([]byte(accessKeySecret))
	return sum[:]
}

func sign(payload []byte, accessKeyID string, key []byte) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.HS256, Key: key},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), accessKeyID),
	)
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}

func encrypt(payload []byte, accessKeyID string, key []byte) (string, error) {
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.A256KW, Key: key, KeyID: accessKeyID},
		nil,
	)
	if err != nil {
		return "", err
	}
	jwe, err := encrypter.Encrypt(payload)
	if err != nil {
		return "", err
	}
	return jwe.CompactSerialize()
}

// ---------------------------------------------------------------------------------------------

func run() error {
	in, err := readInputs()
	if err != nil {
		return err
	}

	payload, err := buildPayload(in)
	if err != nil {
		return err
	}

	if in.mode == "json" {
		// Debug output only: this payload is NOT protected and must not be used as a token.
		fmt.Println(string(payload))
		return nil
	}

	key := deriveKey(in.accessKeySecret)
	var token string
	if in.mode == "jwe" {
		token, err = encrypt(payload, in.accessKeyID, key) // recommended
	} else {
		token, err = sign(payload, in.accessKeyID, key)
	}
	if err != nil {
		return err
	}

	fmt.Println(token)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		flag.Usage()
		os.Exit(1)
	}
}
