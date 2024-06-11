package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (cfg *apiConfig) handlerUsersCreate(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters")
		return
	}

	user, err := cfg.DB.CreateUser(params.Email, params.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't create user")
		return
	}

	respondWithJSON(w, http.StatusCreated, User{
		ID:    user.ID,
		Email: user.Email,
	})
}

func (cfg *apiConfig) handlerLoginUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		ID       int    `json:"id"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't decode parameters")
		return
	}

	user, err := cfg.DB.GetUserByMail(params.Email)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password),[]byte(params.Password) )
	if err != nil {
		fmt.Println(err)
		fmt.Println(user.Password)
		respondWithError(w, http.StatusUnauthorized, "a problem occured")
		return
	}

	respondWithJSON(w, http.StatusOK, User{
		ID:    user.ID,
		Email: user.Email,
	})
}

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MaxCost)
	if err != nil {
		return password, err
	}
	return string(hash), err
}
