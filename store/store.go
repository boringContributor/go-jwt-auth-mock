package store

import (
	"errors"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Name     string
	Password string
}


var inMemoryUser = map[string]string{}

func (user User) AddUser() error {
	if _, ok := inMemoryUser[user.Name]; !ok {
		// todo delete me -> just for testing purpose now
		if len(user.Password) < 8 || len(user.Name) < 3 {
			return errors.New("invalid data: name should contain at least 3 character and password 8")
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		if err != nil {
			panic(err)
		}
		inMemoryUser[user.Name] = string(hashedPassword)
		return nil;
	}
	return errors.New("user already exists")
}

// todo learn how to handle errors properly in go -> this is not the right way
func (user User) GetUser() (User, error) {
	if password, found := inMemoryUser[user.Name]; found {
		err := bcrypt.CompareHashAndPassword([]byte(password), []byte(user.Password))
		if err != nil {
			return User{}, errors.New("not authorized")
		}
		return User{Name: user.Name, Password: password}, nil
	}
	return User{}, errors.New("user does not exist")
}