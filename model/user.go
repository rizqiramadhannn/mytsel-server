package model

type User struct {
	ID          uint   `gorm:"primaryKey"`
	Email       string `json:"email"`
	Password    string `json:"password,omitempty"`
	Name        string
	Pulsa       string
	Internet    string
	Telpon      string
	SMS         string
	Expired     string
	PhoneNumber string
}
