package traefik_jwt_group_access

import (
	"context"
	"log"
	"net/http"
	"slices"

	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	AllowedGroups []string `json:"allowGroups,omitempty"`
	ClaimsPrefix  string   `json:"claimsPrefix"`
	GroupProperty string   `json:"groupProperty"`
}

func CreateConfig() *Config {
	return &Config{
		AllowedGroups: []string{},
	}
}

type JwtGroupAccess struct {
	next http.Handler
	name string

	allowedGroups []string
	claimsPrefix  string
	groupProperty string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &JwtGroupAccess{
		next:          next,
		name:          name,
		allowedGroups: config.AllowedGroups,
		claimsPrefix:  config.ClaimsPrefix,
		groupProperty: config.GroupProperty,
	}, nil
}

func (a *JwtGroupAccess) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	cookie, err := req.Cookie("token")
	if err != nil {
		log.Printf("ERROR DECODING COOKIE 'token': %+v", err)

		// Default closed on error
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	body := cookie.Value

	p := jwt.NewParser()
	token, _, err := p.ParseUnverified(body, jwt.MapClaims{})
	if err != nil {
		log.Printf("CLAIMS ERROR: %+v", err)

		// Default closed on error
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	log.Printf("DECODED TOKEN CLAIMS AS: %+v", token.Claims)

	if m, ok := token.Claims.(jwt.MapClaims); ok {
		var claims map[string]any = m

		if a.claimsPrefix != "" {
			if c, ok := claims[a.claimsPrefix].(map[string]any); ok {
				claims = c
			}
		}

		groupAllowed := false
		if groups, ok := claims[a.groupProperty].([]string); ok {
			for _, group := range a.allowedGroups {
				if slices.Contains(groups, group) {
					groupAllowed = true
					break
				}
			}
		}

		// if their group is not allowed,
		// or their token didn't contain a group property,
		// deny request.
		if !groupAllowed {
			rw.WriteHeader(http.StatusForbidden)
			return
		}

		// if their group is allowed,
		// pass on the request
		a.next.ServeHTTP(rw, req)
	}

	// If there's no claims or we had an error above,
	// reject the request. (DEFAULT FAIL)
	rw.WriteHeader(http.StatusBadRequest)
}
