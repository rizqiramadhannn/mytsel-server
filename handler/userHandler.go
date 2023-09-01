package handler

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"gorm.io/gorm"

	"mytselapp-new/model"
	"mytselapp-new/utils"
)

func RegisterHandler(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		user := new(model.User)
		if err := c.Bind(user); err != nil {
			return c.JSON(http.StatusBadRequest, "Invalid request")
		}

		// Check if the user already exists
		var existingUser model.User
		result := db.Where("email = ?", user.Email).First(&existingUser)
		if result.RowsAffected > 0 {
			return c.JSON(http.StatusConflict, "User already exists")
		}

		// Hash the password (use a secure hashing library like bcrypt)
		hashedPassword, err := utils.HashPassword(user.Password)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, "Error hashing password")
		}

		// Create the new user
		newUser := model.User{
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

func LoginHandler(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		credentials := new(model.User)
		if err := c.Bind(&credentials); err != nil {
			return c.JSON(http.StatusBadRequest, "Invalid request")
		}

		var user model.User
		result := db.Where("email = ?", credentials.Email).First(&user)
		if result.RowsAffected == 0 {
			return c.JSON(http.StatusNotFound, map[string]string{
				"msg": "User not found",
				"rc":  "1001", // You can use an appropriate code for user not found
			})
		}

		// Check if the provided password matches the stored hash
		if !utils.CheckPasswordHash(credentials.Password, user.Password) {
			return c.JSON(http.StatusUnauthorized, map[string]string{
				"msg": "Invalid credentials",
				"rc":  "1002", // You can use an appropriate code for invalid credentials
			})
		}

		// Generate an auth token here
		authToken, err := utils.GenerateAuthToken(user.ID)
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

func GetAllUsersHandler(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		var users []model.User
		result := db.Find(&users)
		if result.Error != nil {
			return c.JSON(http.StatusInternalServerError, "Error fetching users")
		}

		for i := 0; i < len(users); i++ {
			users[i].Password = ""
		}
		return c.JSON(http.StatusOK, users)
	}
}

func GetUserByIDHandler(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		// userID := c.Param("id")
		userID := c.Get("user_id")
		var user model.User
		result := db.First(&user, userID)
		if result.Error != nil {
			return c.JSON(http.StatusNotFound, "User not found")
		}

		user.Password = ""

		return c.JSON(http.StatusOK, user)
	}
}

func GetUserByEmailHandler(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		email := c.Param("email")

		var user model.User
		result := db.Where("email = ?", email).First(&user)
		if result.RowsAffected == 0 {
			return c.JSON(http.StatusNotFound, "User not found")
		}

		return c.JSON(http.StatusOK, user)
	}
}

func DeleteUserByIDHandler(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		userID := c.Param("id")

		result := db.Delete(&model.User{}, userID)
		if result.RowsAffected == 0 {
			return c.JSON(http.StatusNotFound, "User not found")
		}
		if result.Error != nil {
			return c.JSON(http.StatusInternalServerError, "Error deleting user")
		}

		return c.JSON(http.StatusOK, "User deleted successfully")
	}
}
