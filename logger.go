package main

import (
	"log"
)

func init() {
	// todo init logger
}

func infof(format string, args ...interface{}) {
	log.Printf(format, args...)
}
func info(args ...interface{}) {
	log.Println(args...)
}
