package traefik_jwt_group_access

import (
	"context"
	"log"
	"net/http"
	"slices"

	"github.com/golang-jwt/jwt/v5"
)

type Config struct {
	AllowGroups   []string `json:"allowGroups,omitempty"`
	ClaimsPrefix  string   `json:"claimsPrefix"`
	GroupProperty string   `json:"groupProperty"`
}

func CreateConfig() *Config {
	return &Config{
		AllowGroups: make([]string, 0),
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
		allowedGroups: config.AllowGroups,
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

		g, ok := claims[a.groupProperty].([]any)
		if !ok {
			log.Printf("ERROR EXTRACTING GROUPS: %+v %t", g, ok)

			// Default closed on error
			rw.WriteHeader(http.StatusUnauthorized)
			return
		}

		// we should now have a []any in g
		// cast it to []string item by item
		groups := make([]string, len(g))
		for i, v := range g {
			x, ok := v.(string)
			if !ok {
				log.Printf("ERROR: COULD NOT CAST TO STRING: %+v", v)

				// Default closed on error
				rw.WriteHeader(http.StatusUnauthorized)
				return
			}

			groups[i] = x
		}

		// check if their in any group that's allowed through
		groupAllowed := false
		for _, group := range a.allowedGroups {
			log.Printf("DEBUG: CHECKING GROUP: %s", group)
			if slices.Contains(groups, group) {
				groupAllowed = true
				break
			}
		}

		// if their group is not allowed,
		// or their token didn't contain a group property,
		// deny request.
		if !groupAllowed {
			log.Println("GROUP NOT ONE OF ALLOWED GROUPS, FORBIDDEN")
			rw.WriteHeader(http.StatusForbidden)
			return
		}

		// if their group is allowed,
		// pass on the request
		a.next.ServeHTTP(rw, req)
		return
	}

	log.Println("NO CLAIMS DETECTED, FALLTHROUGH")

	// If there's no claims or we had an error above,
	// reject the request. (DEFAULT FAIL)
	rw.WriteHeader(http.StatusBadRequest)
}
