package oidc

import "encoding/json"
import "io/ioutil"
import "net/http"
import "strings"

// import "fmt"

type Registrar struct {
  ApplicationType         string   `json:"application_type"`
  ClientName        string `json:"client_name"`
  ClientID          string `json:"client_id"`
  ClientSecret      string `json:"client_secret"`
  ClientSecretExpiresAt string `json:"client_secret_expires_at"`
  Contacts        []string `json:"contacts"`
  GrantTypes      []string `json:"grant_types"`
  RedirectUris    []string `json:"redirect_uris"`
  ResponseTypes   []string `json:"response_types"`
  RegistrationAccessToken string `json:"registration_access_token"`
  RegistrationClientURI string `json:"registration_client_uri"`
  SubjectType       string `json:"subject_types"`
  TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
  ExpiresAt         string `json:"expires_at"`
}

func Register(registrar *Registrar, registrationEndpoint string) {
  registrar_json, err := json.Marshal(registrar)
  checkError(err)

  reg_response, err := http.Post(registrationEndpoint, "application/json", strings.NewReader(string(registrar_json)))
  checkError(err)
  defer reg_response.Body.Close()

  body, _ := ioutil.ReadAll(reg_response.Body)
  json.Unmarshal([]byte(body), registrar)
}
