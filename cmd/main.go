package main

import (
	"auth-serice/internal/app"
	"os"
)

func main() {
	err := app.Run()
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)

}
