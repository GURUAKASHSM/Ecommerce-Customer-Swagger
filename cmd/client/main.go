package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/kishorens18/ecommerce/cmd/client/docs"
	"github.com/kishorens18/ecommerce/config"
	"github.com/kishorens18/ecommerce/models"
	_ "github.com/kishorens18/ecommerce/models"
	pb "github.com/kishorens18/ecommerce/proto"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"google.golang.org/grpc"
)

type UpdateRequest struct {
	CustomerId string `json:"customerid"`
	Field      string `json:"field"`
	OldValue   string `json:"oldvalue"`
	NewValue   string `json:"newvalue"`
}
type CustomerDBResponse struct {
	Customer_id string `json:"customerid" bson:"customerid"`
}
type PasswordUpdateResponse struct{
	Customer_id string `json:"customerid" bson:"customerid"`
	Message string `json:"message" bson:"message"`
	NewPassword string `json:"newpassword" bson:"newpassword"`
}
type Customer struct {
	CustomerId              string            `json:"customerid" bson:"customerid"`
	Firstname               string            `json:"firstname" bson:"firstname"`
	Lastname                string            `json:"lastname" bson:"lastname"`
	HashesAndSaltedPassword string            `json:"hashesandsaltedpassword" bson:"hashedandsaltedpassword"`
	Email                   string            `json:"email" bson:"email"`
	Address                 []Address         `json:"address" bson:"address"`
	ShippingAddress         []ShippingAddress `json:"shippingaddress" bson:"shippingaddress"`
}
type DeleteRequest struct {
	CustomerId string `json:"customerid" bson:"customerid"`
}
type Address struct {
	Country string `json:"country" bson:"country"`
	Street1 string `json:"street1" bson:"street1"`
	Street2 string `json:"street2" bson:"street2"`
	City    string `json:"city" bson:"city"`
	State   string `json:"state" bson:"state"`
	Zip     string `json:"zip" bson:"zip"`
}
type Token struct {
	Token string `json:"token" bson:"token"`
}
type UpdatePassword struct {
	Email       string `json:"email" bson:"email"`
	OldPassword string `json:"oldpassword" bson:"oldpassword"`
	NewPassword string `json:"newpassword" bson:"newpassword"`
}
type ShippingAddress struct {
	Street1 string `json:"street1" bson:"street1"`
	Street2 string `json:"street2" bson:"street2"`
	City    string `json:"city" bson:"city"`
	State   string `json:"state" bson:"state"`
}

const (
	secretKey = "your-secret-key"
)

type UpdateResponse struct {
	Message string `json:"message" bson:"message"`
}
type DeleteResponse struct {
	Message string `json:"message" bson:"message"`
}
type User struct {
	Email      string `json:"email"`
	Password   string `json:"hashedandsaltedpassword"`
	CustomerId string `json:"customerid"`
}

var (
	mongoclient *mongo.Client
	ctx         context.Context
	server      *gin.Engine
)

// @title Documenting API (Your API Title)
// @version 1
// @Description Sample description

// @contact.name Guru Akash
// @contact.url https://github.com/GURUAKASH-MUTHURAJAN
// @contact.email guuakashsm@gmail.com

// @securityDefinitions.apikey bearer
// @in header
// @name Authorization

// @host localhost:8081
// @BasePath /api/v1

func main() {
	r := gin.Default()

	v1 := r.Group("/api/v1")
	user := v1.Group("/users")
	{
		user.POST("/signup", Signup) // Use "/signup" for signup route
		user.POST("/signin", Signin) // Use "/signin" for signin route
		user.POST("/update", Update)
		user.POST("/delete", Delete)
		user.POST("/reset", Rest)
		user.GET("/getbyid", GetbyId)
		r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
		r.Run(":8081")
	}
}

// CreateUser create new user
// @Summary return created user
// @Description signup
// @Tags Users
// @Accept json
// @Produce json
// @Param user body Customer true "user"
// @Success 200 {object} Customer
// @Router /users/signup [post]
func Signup(c *gin.Context) {
	conn, err := grpc.Dial("localhost:5002", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	client := pb.NewCustomerServiceClient(conn)
	var request pb.CustomerDetails
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	response, err := client.CreateCustomer(c.Request.Context(), &request)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"value": response})
}

// CreateUser create new user
// @Summary return created user
// @Description create and return user
// @Tags Users
// @Param user body User true "User"
// @Success 200 {object} Token
// @Router /users/signin [post]
func Signin(c *gin.Context) {
	conn, err := grpc.Dial("localhost:5002", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	client := pb.NewCustomerServiceClient(conn)
	var user User

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	fmt.Println(user.CustomerId, user.Email)
	if isValidUser(user) {
		token, err := createToken(user.Email, user.CustomerId)

		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Token creation failed"})
			return
		}

		response1, err := client.CreateTokens(c.Request.Context(), &pb.Token{Email: user.Email, Token: token, Customerid: user.CustomerId})
		fmt.Println(response1)

		tokens := Token{Token: token}
		c.JSON(http.StatusOK, gin.H{"value": tokens})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
	}
}
func isValidUser(user User) bool {
	mongoclient, _ := config.ConnectDataBase()
	collection := mongoclient.Database("Ecommerce").Collection("CustomerProfile")
	filter := bson.M{"email": user.Email, "hashedandsaltedpassword": user.Password, "customerid": user.CustomerId}
	count, err := collection.CountDocuments(ctx, filter)
	if err != nil {

		fmt.Println("ERROR")
		return false
	}
	return count > 0
}

func createToken(email, customerid string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email, "customerid": customerid,
		"exp": time.Now().Add(time.Hour * 1).Unix(),
	})
	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

// Update the Created User
// @Summary Update User
// @Description Update and return user
// @Tags Users
// @Accept json
// @Produce json
// @Param user body UpdateRequest true "User"
// @Success 200 {object} UpdateResponse
// @Router /users/update [post]
func Update(c *gin.Context) {
	conn, err := grpc.Dial("localhost:5002", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	client := pb.NewCustomerServiceClient(conn)
	var user models.UpdateRequest
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	updatedUser, err := client.UpdateCustomer(c.Request.Context(), &pb.UpdateDetails{CustomerId: user.CustomerId,
		Field: user.Field, OldValue: user.OldValue, NewValue: user.NewValue})
	fmt.Println(updatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}
	Response := UpdateResponse{Message: "Updated"}
	c.JSON(http.StatusOK, gin.H{"value": Response})
}

// DeleteUser delete exsisting user
// @Summary return Deleted Message
// @Description Delete
// @Tags Users
// @Accept json
// @Produce json
// @Param user body DeleteRequest true "user"
// @Success 200 {object} DeleteResponse
// @Router /users/delete [post]
func Delete(c *gin.Context) {
	conn, err := grpc.Dial("localhost:5002", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	client := pb.NewCustomerServiceClient(conn)
	var user models.DeleteRequest

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	client.DeleteCustomer(c.Request.Context(), &pb.DeleteDetails{CustomerID: user.CustomerId})
	Response := DeleteResponse{Message: "User Deleted"}
	c.JSON(http.StatusOK, gin.H{"value": Response})

}
// ResetPassword reset user Password
// @Summary return Updated Password
// @Description reset
// @Tags Users
// @Accept json
// @Produce json
// @Param user body UpdatePassword true "user"
// @Success 200 {object} UpdatePassword
// @Router /users/reset [post]
 func Rest(c *gin.Context) {
	conn, err := grpc.Dial("localhost:5002", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	client := pb.NewCustomerServiceClient(conn)
	var user models.UpdatePassword
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	response, err := client.UpdatePassword(c.Request.Context(), &pb.PasswordDetails{Email: user.Email, OldPassword: user.OldPassword, NewPassword: user.NewPassword})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
    Response := PasswordUpdateResponse{Message: "Password Updated",Customer_id: response.Customer_ID,NewPassword: user.NewPassword}
	c.JSON(http.StatusOK, gin.H{"value": Response})
}
// Update the Created User
// @Summary Update User
// @Description Update and return user
// @Security bearerToken
// @Tags Users
// @Success 200 {object} UpdatePassword
// @Router /users/getbyid [get]
func GetbyId (c *gin.Context) {
	conn, err := grpc.Dial("localhost:5002", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()
	client := pb.NewCustomerServiceClient(conn)
	token := c.GetHeader("Authorization")
	result, err := client.GetByCustomerId(c.Request.Context(), &pb.GetbyId{Token: token})
	if err != nil {
		fmt.Println("Error:", err.Error()) // Print the error message for debugging
		c.JSON(http.StatusBadGateway, gin.H{"status": "fail", "message": err.Error()})
	}
	c.JSON(http.StatusCreated, gin.H{"status": "success", "data": result})
}