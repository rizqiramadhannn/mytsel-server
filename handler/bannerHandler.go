package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"gorm.io/gorm"

	"mytselapp-new/model"
)

func AddBannerHandler(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		banner := new(model.Banner)
		if err := c.Bind(banner); err != nil {
			return c.JSON(http.StatusBadRequest, "Invalid request")
		}

		// Create the new user
		newBanner := model.Banner{
			Name: banner.Name,
			URL:  banner.URL,
		}
		db.Create(&newBanner)

		return c.JSON(http.StatusCreated, "Banner registered successfully")
	}
}

func GetBannerHandler(db *gorm.DB) echo.HandlerFunc {
	return func(c echo.Context) error {
		var banners []model.Banner
		result := db.Find(&banners)
		if result.Error != nil {
			return c.JSON(http.StatusInternalServerError, "Error fetching banners")
		}

		return c.JSON(http.StatusOK, banners)
	}
}
