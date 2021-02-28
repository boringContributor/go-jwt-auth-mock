package main

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"go_auth/auth"
	"go_auth/store"
	"log"
	"net/http"
	"os"
)
type ErrorResponse struct {
	Status string `json:"status"`
	Error  string  `json:"error"`
}

// todo how to make go struct params optional?
type Success struct {
	Success bool
	Token string
}
func handleSignUp(c *gin.Context) {
	var user store.User
	if err := c.ShouldBindJSON(&user); err != nil {
		log.Print(err)
		c.JSON(http.StatusBadRequest, gin.H{"msg": err})
		return
	}
	err := user.AddUser()
	log.Print(err)
	if err != nil {
		c.JSON(http.StatusConflict, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"new user": user.Name})
}


func handleLogin(c *gin.Context)  {
	var user store.User
	if err := c.ShouldBindJSON(&user); err != nil {
		log.Print(err)
		c.JSON(http.StatusBadRequest, gin.H{"msg": err})
		return
	}
	_, userError := user.GetUser()
	log.Print(userError)
	if userError != nil {
		errRes := ErrorResponse{"Error", userError.Error()}
		response, _ := json.Marshal(errRes)
		c.JSON(http.StatusBadRequest, response)
		return
	}
	token, tokenError := auth.CreateToken(user.Name)
	if tokenError != nil {
		errRes := ErrorResponse{"Error", tokenError.Error()}
		response, _ := json.Marshal(errRes)
		c.JSON(http.StatusBadRequest, response)
		return
	}
	// todo that is not nice see struct comment at success struct
	c.JSON(http.StatusAccepted, Success{
		Success: token != "",
		Token:   token,
	})
}

func handleTest(c *gin.Context)  {
	token, error := auth.VerifyToken(c)

	if error != nil {
		c.JSON(http.StatusBadRequest, error)
	}
	c.JSON(http.StatusOK, token)
}
func main() {
	port := os.Getenv("PORT")

	if port == "" {
		port = "8080"
		log.Printf("Defaulting to port %s", port)
	}

	r := gin.Default()

	r.POST("/login/", handleLogin)
	r.POST("/signup/", handleSignUp)
	r.GET("/test", handleTest)
	r.Run()
}
