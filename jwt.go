package oidc

import "fmt"
import "strings"
import "encoding/json"
import "crypto/rsa"
import "crypto/sha256"
import "crypto/ecdsa"
import "crypto"
import "encoding/base64"
import "github.com/square/go-jose"

type JWT struct {
  Header         string
  Payload        string
  Signature      string
  DecodedHeader  *decodedHeader
  DecodedPayload *decodedPayload
}

type decodedHeader struct {
  Alg string `json:"alg"`
  Kid string `json:"kid"`
  Use string `json:"use"`
  Typ string `json:"typ"`
}

type decodedPayload struct {
  Iss string      `json:"iss"`
  Sub string      `json:"sub"`
  // Aud []string
  Aud string      `json:"aud"`
  Exp string      `json:"exp"`
  Iat string      `json:"iat"`
  AuthTime string `json:"auth_time"`
  Nonce string    `json:"nonce"`
}

func NewJWT(jwt string) (*JWT, error) {
  parts := strings.Split(jwt, ".")
  if len(parts) != 3 {
    return nil, fmt.Errorf("oidc: invalid JWT received, JWT must have 3 parts")
  }

  return &JWT{
    Header:    parts[0],
    Payload:   parts[1],
    Signature: parts[2],
  }, nil
}

func (j *JWT) Decode() (error) {
  headerBytes, err := decodeBase64ToByte(j.Header)
  if err != nil {
    return err
  }
  json.Unmarshal(headerBytes, &j.DecodedHeader)
  fmt.Println("Header: ", j.DecodedHeader)
  payloadBytes, err := decodeBase64ToByte(j.Payload)
  if err != nil {
    return err
  }
  json.Unmarshal(payloadBytes, &j.DecodedPayload)
  fmt.Println("Payload: ", j.DecodedPayload)

  return nil
}

func (j *JWT) Verify(nonce, issuer string, registrar *Registrar) ([]error) {
  j.Decode()
  payload := j.DecodedPayload
  errors := []error{}

  if nonce != "" && payload.Nonce != nonce {
    errors = append(errors, fmt.Errorf("oidc: IDToken(JWT) nonce mismatch - expected: %v, got: %v", nonce, payload.Nonce))
  }
  if payload.Iat == "" {
    errors = append(errors, fmt.Errorf("oidc: IDToken(JWT) missing required JWT property iat"))
  }
  if payload.Sub == "" {
    errors = append(errors, fmt.Errorf("oidc: IDToken(JWT) missing required JWT property sub"))
  }
  if payload.Aud == "" || payload.Aud != registrar.ClientID {
    errors = append(errors, fmt.Errorf("oidc: IDToken(JWT) aud is missing the client_id, expected %v to be included in %v", registrar.ClientID, payload.Aud))
  }
  if issuer != payload.Iss {
    errors = append(errors, fmt.Errorf("oidc: IDToken(JWT) iss mismatch - expected: %v, got: %v", issuer, payload.Iss))
  }

  return errors
}

func (j *JWT) VerifySignature(set *jose.JSONWebKeySet) (bool, error) {
  signatureBytes, err := decodeBase64ToByte(j.Signature)
  if err != nil {
    return false, err
  }
  if string(signatureBytes) == "" {
    fmt.Println("oidc: JOSE header kid missing")
  }

  payload := j.Header + "." + j.Payload
  h := sha256.New()
  h.Write([]byte(payload))

  for _, key := range set.Keys {
    switch key.Key.(type) {
      case *rsa.PublicKey:
        fmt.Printf("oidc:idtoken: RSAkeyID: %T, %v\n", key, key)
        err = rsa.VerifyPKCS1v15(key.Key.(*rsa.PublicKey), crypto.SHA256, h.Sum(nil), signatureBytes)
        if err == nil {
          return true, nil
        }
      case *ecdsa.PublicKey:
        fmt.Printf("oidc:idtoken: ECkeyID: %T, %v\n", key, key)
        ok := ecdsa.Verify(key.Key.(*ecdsa.PublicKey), h.Sum(nil), key.X, key.Y)
        if ok {
          return true, nil
        }
      default:
        fmt.Printf("oidc:idtoken: No PublicKey: %v\n", key.KeyID)
    }
  }

  return false, nil
}

func decodeBase64ToByte(base64String string) ([]byte, error) {
  decoded, err := base64.RawURLEncoding.DecodeString(base64String)
  if err != nil {
    return nil, err
  }
  return decoded, nil
}

