package oidc

import "fmt"
import "log"
import "net/http"
import "io/ioutil"
import "encoding/json"
import "github.com/square/go-jose"

type config struct {
  AuthorizationEndpoint string             `json:"authorization_endpoint"`
  RegistrationEndpoint  string `json:"registration_endpoint"`
  TokenEndpoint         string `json:"token_endpoint"`
  UserinfoEndpoint      string `json:"userinfo_endpoint"`
  ScopesSupported     []string `json:"scopes_supported"`
  JWKSUri               string `json:"jwks_uri"`
  JWKS      jose.JSONWebKeySet `json:"jwks"`

}

var Config config

func checkError(e error){
  if e != nil {
    log.Fatal(e)
  }
}

func readBodyFrom(path string) ([]byte){
  res, err := http.Get(path + "/.well-known/openid-configuration/")
  checkError(err)
  body, err := ioutil.ReadAll(res.Body)
  res.Body.Close()
  checkError(err)
  return body
}

func GetOIDCConfiguration(issuer string) {
  fmt.Printf("oidc: fetchng OpenIDCConnect Configuration from %s\n", issuer)
  body := readBodyFrom(issuer)
  json.Unmarshal([]byte(body), &Config)
}

func (c *config) GetJSONWebKeySet() (error) {
  fmt.Printf("oidc: fetchng JSONWebKeySet from %s\n", c.JWKSUri)
  resp, err := http.Get(c.JWKSUri)
  if err != nil {
    return err
  }

  defer resp.Body.Close()
  if resp.StatusCode != 200 {
    return fmt.Errorf("oidc: failed request, status: %d", resp.StatusCode)
  }

  jsonWebKeySet := new(jose.JSONWebKeySet)
  if err = json.NewDecoder(resp.Body).Decode(jsonWebKeySet); err != nil {
    return err
  }

  c.JWKS = *jsonWebKeySet
  return nil
}

func (c *config) GetJSONWebKey(keyId string) (*jose.JSONWebKey, error) {
  keys := c.JWKS.Key(keyId)
  if len(keys) == 0 {
    return nil, fmt.Errorf("JWK is not found: %s", keyId)
  }

  for _, jwk := range keys {
    return &jwk, nil
  }
  return nil, fmt.Errorf("JWK is not found %s", keyId)
}
