package main

import (
	"JWT_Authentication_Demo/api"
	"JWT_Authentication_Demo/model"
	"JWT_Authentication_Demo/services"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
)

// user model
type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type JWT struct {
	Token string `json:"token"`
}

func main() {

	// get database connection

	router := mux.NewRouter()
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protectedApi", services.TokenVerifyMiddleware(protectedFunction)).Methods("POST")

	// start the http server
	log.Println("Server is started on port 8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}

func RespondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func signup(w http.ResponseWriter, req *http.Request) {
	log.Println("Inside signup")
	db := api.GetConnection()
	defer db.Close()
	user := User{}
	var error model.Error
	// extract request data
	err := json.NewDecoder(req.Body).Decode(&user)
	if err != nil {
		error.Message = err.Error()
		services.RespondWithError(w, http.StatusBadRequest, error)
		return
	}
	// user input validation
	if user.Email == "" {
		error.Message = "Email must not be empty"
		services.RespondWithError(w, http.StatusBadRequest, error)
		return
	}
	if user.Password == "" {
		error.Message = "Password must not be empty"
		services.RespondWithError(w, http.StatusBadRequest, error)
		return
	}
	// encrypt credentials
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		error.Message = err.Error()
		services.RespondWithError(w, http.StatusInternalServerError, error)
		return
	}
	stmt, err := db.Prepare("INSERT INTO LOGIN(EMAIL, PASSWORD) VALUES(?,?)")
	if err != nil {
		error.Message = err.Error()
		services.RespondWithError(w, http.StatusInternalServerError, error)
		return
	}
	result, err := stmt.Exec(user.Email, hashedPassword)
	if err != nil {
		error.Message = err.Error()
		services.RespondWithError(w, http.StatusInternalServerError, error)
		return
	}
	fmt.Println(result)
}
func login(w http.ResponseWriter, req *http.Request) {
	log.Println("Inside login")
	var error model.Error
	user := User{}
	var jwt JWT
	err := json.NewDecoder(req.Body).Decode(&user)
	if err != nil {
		error.Message = err.Error()
		services.RespondWithError(w, http.StatusInternalServerError, error)
		return
	}
	claims := model.Claims{
		UserClaims: map[string]interface{}{
			"email": user.Email,
		},
		ExpiresAt: time.Now().Add(time.Second * 20).Unix(),
	}
	token := services.GenerateToken(claims, "secret")
	log.Println(token)
	jwt.Token = token
	RespondJSON(w, http.StatusOK, jwt)
	return
}
func protectedFunction(w http.ResponseWriter, req *http.Request) {
	log.Println("Inside protectedFunction")
	fmt.Println(services.GetJWTClaims(req))
}
