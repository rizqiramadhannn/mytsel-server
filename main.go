package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	//"github.com/rizqiramadhannn/mytsel-server/config"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func main() {
	// Replace with your actual MariaDB connection details
	dsn := "root:1234@tcp(localhost:3306)/mytseldb?charset=utf8mb4&parseTime=True&loc=Local"

	// Connect to the database
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to the database")
	}

	// AutoMigrate will create tables for your models if they don't exist
	db.AutoMigrate(&User{})
	db.AutoMigrate(&Banner{})

	// Initialize Echo
	e := echo.New()

	// Apply middleware to group
	protectedGroup := e.Group("")
	protectedGroup.Use(authenticate)

	// Set up routes
	e.POST("/register", registerHandler(db))
	e.POST("/login", loginHandler(db))
	protectedGroup.GET("/users", getAllUsersHandler(db))
	protectedGroup.GET("/user/:id", getUserByIDHandler(db))
	protectedGroup.GET("/user/:email", getUserByEmailHandler(db))
	protectedGroup.DELETE("/user/:id", deleteUserByIDHandler(db))
	protectedGroup.POST("/addBanner", addBannerHandler(db))
	protectedGroup.GET("/banner", getBannerHandler(db))
	// Start the server
	e.Start(":8080")
}

type User struct {
	ID          uint `gorm:"primaryKey"`
	Email       string
	Password    string
	Name        string
	Pulsa       string
	Internet    string
	Telpon      string
	SMS         string
	Expired     string
	PhoneNumber string
}

type Banner struct {
	ID   uint `gorm:"primaryKey"`
	Name string
	URL  string
}

func authenticate(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		token := c.Request().Header.Get("Authorization")
		if token == "" {
			return c.JSON(http.StatusUnauthorized, map[string]string{"msg": "Missing token"})
		}

		// Extract the token by removing the "Bearer " prefix
		token = strings.TrimPrefix(token, "Bearer ")

		// Parse the token
		claims := jwt.MapClaims{}
		parsedToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			// Replace with your actual secret key used for signing the tokens
			return []byte("1234"), nil
		})
		fmt.Println("Token String:", token)
		fmt.Println("Parsed Token:", parsedToken.Valid)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, map[string]string{"msg": "Invalid token"})
		}

		// Check expiration
		if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
			return c.JSON(http.StatusUnauthorized, map[string]string{"msg": "Token has expired"})
		}

		// If the token is valid, call the next handler
		return next(c)
	}
}

func addBannerHandler(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		banner := new(Banner)
		if err := c.Bind(banner); err != nil {
			return c.JSON(http.StatusBadRequest, "Invalid request")
		}

		// Create the new user
		newBanner := Banner{
			Name: banner.Name,
			URL:  banner.URL,
		}
		db.Create(&newBanner)

		return c.JSON(http.StatusCreated, "Banner registered successfully")
	}
}

func registerHandler(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		user := new(User)
		if err := c.Bind(user); err != nil {
			return c.JSON(http.StatusBadRequest, "Invalid request")
		}

		// Check if the user already exists
		var existingUser User
		result := db.Where("email = ?", user.Email).First(&existingUser)
		if result.RowsAffected > 0 {
			return c.JSON(http.StatusConflict, "User already exists")
		}

		// Hash the password (use a secure hashing library like bcrypt)
		hashedPassword, err := hashPassword(user.Password)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, "Error hashing password")
		}

		// Create the new user
		newUser := User{
			Email:       user.Email,
			Password:    hashedPassword,
			Name:        user.Name,
			Pulsa:       "0",
			Internet:    "0",
			Telpon:      "0",
			SMS:         "0",
			Expired:     time.Now().AddDate(0, 1, 0).String(),
			PhoneNumber: "085200000000",
		}
		err = db.Create(&newUser).Error
		if err != nil {
			return c.JSON(http.StatusInternalServerError, "Email error")
		}
		//validasi email & len email
		return c.JSON(http.StatusCreated, "User registered successfully")
	}
}

func loginHandler(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		credentials := struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}{}
		if err := c.Bind(&credentials); err != nil {
			return c.JSON(http.StatusBadRequest, "Invalid request")
		}

		var user User
		result := db.Where("email = ?", credentials.Email).First(&user)
		if result.RowsAffected == 0 {
			return c.JSON(http.StatusNotFound, map[string]string{
				"msg": "User not found",
				"rc":  "1001", // You can use an appropriate code for user not found
			})
		}

		// Check if the provided password matches the stored hash
		if !checkPasswordHash(credentials.Password, user.Password) {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"msg": "Invalid credentials",
				"rc":  "1002", // You can use an appropriate code for invalid credentials
			})
		}

		// Generate an auth token here
		authToken, err := generateAuthToken(user.ID)
		if err != nil {
			// Handle token generation error
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"msg": "Token generation error",
				"rc":  "1003", // You can use an appropriate code for token generation error
			})
		}

		return c.JSON(http.StatusOK, map[string]string{
			"msg":   "Login successful",
			"rc":    "0",
			"token": authToken,
		})
	}
}

func getAllUsersHandler(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		var users []User
		result := db.Find(&users)
		if result.Error != nil {
			return c.JSON(http.StatusInternalServerError, "Error fetching users")
		}

		return c.JSON(http.StatusOK, users)
	}
}

func getBannerHandler(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		var banners []Banner
		result := db.Find(&banners)
		if result.Error != nil {
			return c.JSON(http.StatusInternalServerError, "Error fetching banners")
		}

		return c.JSON(http.StatusOK, banners)
	}
}

func getUserByIDHandler(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		userID := c.Param("id")

		var user User
		result := db.First(&user, userID)
		if result.Error != nil {
			return c.JSON(http.StatusNotFound, "User not found")
		}

		return c.JSON(http.StatusOK, user)
	}
}

func getUserByEmailHandler(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		email := c.Param("email")

		var user User
		result := db.Where("email = ?", email).First(&user)
		if result.RowsAffected == 0 {
			return c.JSON(http.StatusNotFound, "User not found")
		}

		return c.JSON(http.StatusOK, user)
	}
}

func deleteUserByIDHandler(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		userID := c.Param("id")

		result := db.Delete(&User{}, userID)
		if result.RowsAffected == 0 {
			return c.JSON(http.StatusNotFound, "User not found")
		}
		if result.Error != nil {
			return c.JSON(http.StatusInternalServerError, "Error deleting user")
		}

		return c.JSON(http.StatusOK, "User deleted successfully")
	}
}

func hashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedBytes), nil
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateAuthToken(userId uint) (string, error) {
	// Create a new token
	token := jwt.New(jwt.SigningMethodHS256)

	// Set claims (payload)
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = userId
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix() // Token expiration time (1 day)

	// Sign the token with a secret key
	secretKey := []byte("1234")
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", err
	}

	// Token validation
	claimed := jwt.MapClaims{}
	parsedToken, err := jwt.ParseWithClaims(tokenString, claimed, func(token *jwt.Token) (interface{}, error) {
		// Replace with your actual secret key used for signing the tokens
		return []byte("1234"), nil
	})

	if err != nil {
		fmt.Println("Token validation error:", err)
	}

	fmt.Println("Parsed Token:", parsedToken.Valid)
	fmt.Println("Token String:", tokenString)

	return tokenString, nil
}
