package services

import (
	"JWT_Authentication_Demo/model"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/davecgh/go-spew/spew"

	jwt "github.com/dgrijalva/jwt-go"
)

// Generates the token with specified claims and signs it with secret key
func GenerateToken(claims model.Claims, secretKey string) string {
	jwtClaims := constructClaims(claims)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
	model.JWT_SECRET_KEY = secretKey
	// signs the token and returns signed token
	signedToken, err := token.SignedString([]byte(model.JWT_SECRET_KEY))
	if err != nil {
		log.Fatal(err)
	}
	return signedToken
}

// middleware that returns handler which validates JWT token
func TokenVerifyMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// get the authorization header
		authHeader := req.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) == 2 {
			// token string is at 1th index
			authToken := bearerToken[1]
			var errObj model.Error
			token, err := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}
				return []byte(model.JWT_SECRET_KEY), nil
			})
			if claims := token.Claims.(jwt.MapClaims); claims != nil && token.Valid {
				spew.Dump(token)
				next.ServeHTTP(w, req)
			} else if err != nil {
				errObj.Message = err.Error()
				RespondWithError(w, http.StatusInternalServerError, errObj)
				return
			}
		}
	})
}

func GetJWTClaims(req *http.Request) (jwt.MapClaims, error) {
	jwtClaims := jwt.MapClaims{}
	// get the authorization header
	authHeader := req.Header.Get("Authorization")
	bearerToken := strings.Split(authHeader, " ")
	if len(bearerToken) == 2 {
		// token string is at 1th index
		authToken := bearerToken[1]
		token, err := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(model.JWT_SECRET_KEY), nil
		})
		if jwtClaims := token.Claims.(jwt.MapClaims); jwtClaims != nil && token.Valid {
			return jwtClaims, nil
		} else if err != nil {
			return jwtClaims, err
		}
	}
	return jwtClaims, errors.New("Invalid token")
}

// method to construct jwt claims from user specified claims
func constructClaims(claims model.Claims) jwt.MapClaims {
	jwtClaims := jwt.MapClaims{}
	// set user specific claims
	for claimKey, claimValue := range claims.UserClaims {
		jwtClaims[claimKey] = claimValue
	}
	// set standard Claims
	jwtClaims["aud"] = claims.Audience
	jwtClaims["exp"] = claims.ExpiresAt
	jwtClaims["jti"] = claims.Id
	jwtClaims["iat"] = claims.IssuedAt
	jwtClaims["iss"] = claims.Issuer
	jwtClaims["nbf"] = claims.NotBefore
	jwtClaims["sub"] = claims.Subject
	return jwtClaims
}
