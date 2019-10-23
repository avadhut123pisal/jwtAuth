package services

import (
	"jwtAuth/model"
	"encoding/json"
	"net/http"
)

func RespondWithError(w http.ResponseWriter, status int, err model.Error) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(err)
}
