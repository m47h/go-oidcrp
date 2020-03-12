```
package main

import "fmt"
import "log"
import "net/http"
import "io/ioutil"
import "os/exec"

import "golang.org/x/oauth2"
import "github.com/m47h/go-oidcrp"

var (
  Issuer       = "https://rp.certification.openid.net:8080/debbie-test/rp-id_token-sig-rs256"
  RedirectUris = []string{"http://localhost:8080/ce"}
  registrar    = oidc.Registrar{
    ApplicationType: "web",
    ClientName: "Debb",
    Contacts: []string{"dummy@test.com"},
    GrantTypes: []string{"authorization_code"},
    RedirectUris: RedirectUris,
    ResponseTypes: []string{"code"},
  }
)

func main() {
  oidc.GetOIDCConfiguration(Issuer)
  oidc.Register(&registrar, oidc.Config.RegistrationEndpoint)
  oidcClient := &oidc.OIDCClient{
    &oauth2.Config{
      registrar.ClientID,
      registrar.ClientSecret,
      oauth2.Endpoint{
        AuthURL: oidc.Config.AuthorizationEndpoint,
        TokenURL: oidc.Config.TokenEndpoint,
        AuthStyle: 0,
      },
      RedirectUris[0],
      []string{"profile", "openid"},
    },
    "code",
  }
  oidc.Config.GetJSONWebKeySet()

  oidcParams := oidc.OIDCAuthCodeURLInput{
    Nonce: "nonce-abcdefghijkasdfasdf123123123",
    State: "state-xxxxxxxxxxxx",
  }
  authPath := oidcClient.GetAuthCodeURL(oidcParams)

  cmd := exec.Command(
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    authPath,
    "--user-data-dir=test-user-data",
  )
  if err := cmd.Start(); err != nil {
    log.Fatalln("can't open browser", err)
  }
  defer cmd.Process.Kill()

  http.HandleFunc("/ce", func(w http.ResponseWriter, r *http.Request){
    oidcToken, err := oidcClient.Exchange(oauth2.NoContext, r.URL.Query().Get("code"))
    if err != nil {
      log.Fatal(err)
    }

    idToken := oidcToken.Extra("id_token").(string)
    jwt, _ := oidc.NewJWT(idToken)
    warnings := jwt.Verify(oidcParams.Nonce, Issuer, &registrar)
    if len(warnings) > 0 {
      for _, v := range warnings { fmt.Println(v) }
    }

    signatureValid, err := jwt.VerifySignature(&oidc.Config.JWKS)
    if err != nil { fmt.Printf("oidc:idtoken: %v\n", err) }
    if signatureValid {
      fmt.Println("oidc:idtoken: SUCCESS JSONWebSignature(JWS) Verification")
    } else {
      fmt.Println("oidc:idtoken: FAILED JSONWebSignature(JWS) Verification")
    }

    client := oidcClient.Client(oauth2.NoContext, oidcToken)

    res, err := client.Get(oidc.Config.UserinfoEndpoint)
    if err != nil {
      log.Fatal(err)
    }
    body, err := ioutil.ReadAll(res.Body)
    res.Body.Close()
    fmt.Println("oidc:userinfo:", string(body))
  })

  log.Fatal(http.ListenAndServe(":8080", nil))
}

```
