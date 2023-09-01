package model

type Banner struct {
	ID   uint `gorm:"primaryKey"`
	Name string
	URL  string
}
