//go:build !windows

package main

import "fmt"

func showMessage(title, text string) {
	fmt.Println(title, ":", text)
}
