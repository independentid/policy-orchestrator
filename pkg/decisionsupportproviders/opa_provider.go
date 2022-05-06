package providers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type OpaDecisionProvider struct {
	Client HTTPClient
	Url    string
}

type OpaQuery struct {
	Input map[string]interface{} `json:"input"`
}

func (o OpaDecisionProvider) BuildInput(r *http.Request) (any interface{}, err error) {
	sub, err := PrepareSubjectInfo(r)
	if err != nil {
		log.Printf("Error parsing & validating subject: %v", err.Error())
	}
	req := PrepareReqParams(r)
	return OpaQuery{map[string]interface{}{
		"req":     req,
		"subject": sub,
	}}, nil
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type OpaResponse struct {
	Result   bool     `json:"result"`
	Allow    bool     `json:"allow"`
	AllowSet []string `json:"allowSet"`
}

func (o OpaDecisionProvider) Allow(any interface{}) (bool, error) {
	marshal, _ := json.Marshal(any.(OpaQuery))
	request, _ := http.NewRequest("POST", o.Url, bytes.NewBuffer(marshal))
	request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	response, err := o.Client.Do(request)
	if err != nil {
		return false, err
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(response.Body)

	var jsonResponse OpaResponse
	err = json.NewDecoder(response.Body).Decode(&jsonResponse)
	if err != nil {
		return false, err
	}

	return jsonResponse.Result, nil
}

// ReqParams provides information about the
type ReqParams struct {
	ClientIp   string              `json:"ip"`
	Protocol   string              `json:"protocol"`
	Method     string              `json:"method"`
	Path       string              `json:"path"`
	QueryParam map[string][]string `json:"param"`
	Header     map[string][]string `json:"header,omitempty"`
	Time       time.Time           `json:"time"` //Unix time
}

// SubjectInfo holds information about the Subject performing a request
type SubjectInfo struct {
	ProvId    string                 `json:"provId,omitempty"`
	Roles     []string               `json:"roles,omitempty"`
	Claims    map[string]interface{} `json:"claims,omitempty"`
	Expires   int64                  `json:"expires,omitempty"`
	Type      string                 `json:"type,omitempty"`
	Sub       string                 `json:"sub,omitempty"`
	Issuer    string                 `json:"iss,omitempty"`
	Audience  string                 `json:"aud,omitempty"`
	IssuedAt  int64                  `json:"iat,omitempty"` //Unix time
	NotBefore int64                  `json:"nbf,omitempty"`
}

// HexaClaims declares the standard claims plus roles claim used by Hexa (used by JWT)
type HexaClaims struct {
	*jwt.StandardClaims
	Roles string `json:"roles"`
}

// PrepareSubjectInfo identifies the authenticated subject (Basic, Bearer, Anonymous) and returns a SubjectInfo
func PrepareSubjectInfo(r *http.Request) (*SubjectInfo, error) {
	verifyKey := os.Getenv("OPATOOLS_JWTVERIFYKEY")

	hexaClaims := HexaClaims{}

	info := SubjectInfo{}
	authz := r.Header.Get("Authorization")
	if authz != "" {
		parts := strings.Split(authz, " ")
		if strings.EqualFold(parts[0], "bearer") {
			bearer := parts[1]

			// At this point, this assumes the bearer token is a JWT (not always true!)
			// TODO: Add handling for other bearer types such as SAML
			if verifyKey == "" {
				log.Println("Verify key undefined (OPATOOLS_JWTVERIFYKEY)")
				return nil, errors.New("Token verify misconfigured")
			} else {
				// Try to verify as signed JWT
				_, err := jwt.ParseWithClaims(bearer, &hexaClaims, func(token *jwt.Token) (interface{}, error) {
					return []byte(verifyKey), nil
				})

				if err != nil {
					log.Println("Token parsing/validation failed: " + err.Error())
					info.MapJwtClaims(hexaClaims, fmt.Sprintf("Invalid (%s)", err.Error()))
					return &info, err
				}
			}

			info.MapJwtClaims(hexaClaims, "Bearer+JWT")

		} else if strings.EqualFold(parts[0], "basic") {
			username, _, ok := r.BasicAuth()
			if ok {
				info.Type = "basic"
				info.Sub = username
			}
		} else {
			// This is done for diagnostic purposes
			info.Type = fmt.Sprintf("Unknown-%s", strings.Split(authz, " ")[0])
			log.Println("Unknown authorization type: " + info.Type)
		}
	} else {
		info.Type = "Anonymous"
	}

	return &info, nil
}

// MapJwtClaims extracts the claims from the JWT and places them in the SubjectInfo object
func (info *SubjectInfo) MapJwtClaims(claims HexaClaims, tknType string) {
	info.Type = tknType
	info.Sub = claims.Subject
	info.Audience = claims.Audience
	info.NotBefore = claims.NotBefore
	info.IssuedAt = claims.IssuedAt
	info.Issuer = claims.Issuer
	info.Expires = claims.ExpiresAt

	roleStr := claims.Roles
	info.Roles = strings.Split(strings.ToLower(roleStr), " ")
}

// PrepareReqParams takes commonly used attributes from http.Request and populates ReqParams
func PrepareReqParams(r *http.Request) *ReqParams {
	var resp ReqParams
	resp.ClientIp = r.RemoteAddr
	resp.Time = time.Now()

	resp.Path = r.URL.Path
	resp.QueryParam = r.URL.Query()
	resp.Protocol = r.Proto
	resp.Method = r.Method
	resp.Header = r.Header

	return &resp
}
