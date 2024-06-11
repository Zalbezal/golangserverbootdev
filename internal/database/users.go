package database

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (db *DB) CreateUser(email, password string) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	hashed_password, err := HashPassword(password)
	if err != nil {
		return User{}, err
	}

	id := len(dbStructure.Users) + 1
	user := User{
		ID:       id,
		Email:    email,
		Password: hashed_password,
	}
	for i := 0; i < len(dbStructure.Users)+1; i++ {
		if dbStructure.Users[i].Email == user.Email {
			return User{}, errors.New("that email is already in use")
		}
	}

	dbStructure.Users[id] = user

	err = db.writeDB(dbStructure)
	if err != nil {
		return User{}, err
	}

	return user, nil
}

func (db *DB) GetUser(id int) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return User{}, err
	}

	user, ok := dbStructure.Users[id]
	if !ok {
		return User{}, ErrNotExist
	}

	return user, nil
}

func (db *DB) GetUserByMail(email string) (User, error) {
	dbStructure, err := db.loadDB()
	if err != nil {

		return User{}, err
	}
	for i := 0; i < len(dbStructure.Users)+1; i++ {
		if email == dbStructure.Users[i].Email {
			return dbStructure.Users[i], nil
		}
	}
	return User{}, ErrNotExist

}

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return password, err
	}
	return string(hash), err
}
