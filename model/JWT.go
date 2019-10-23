package model

var (
	JWT_SECRET_KEY = ""
)

type Claims struct {
	UserClaims map[string]interface{}
	Audience   string
	ExpiresAt  int64
	Id         string
	IssuedAt   int64
	Issuer     string
	NotBefore  int64
	Subject    string
}
