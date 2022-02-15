package main

import (
	"time"

	"gorm.io/gorm"
)

//
type File struct {
	gorm.Model
	ID        string `gorm:"primary_key"`
	Path      string
	CreatedAt time.Time
	UpdatedAt time.Time
}
