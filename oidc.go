package oidc

// import "fmt"

// import "net/http"

// import "log"
// import "strings"
// import "encoding/base64"
// import "encoding/json"
// import "errors"
// import "bytes"

import "golang.org/x/oauth2"

// import "golang.org/x/oauth2/jws"

type OIDCClient struct {
  *oauth2.Config
  ResponseType string
}

type OIDCAuthCodeURLInput struct {
  Nonce string
  State string
}

func (oidcc *OIDCClient) GetAuthCodeURL(in OIDCAuthCodeURLInput) string {
  // oidcc.RedirectURL = in.RedirectURI
  return oidcc.AuthCodeURL(in.State,
    oauth2.AccessTypeOnline,
    oauth2.SetAuthURLParam("nonce", in.Nonce),
  )
}
