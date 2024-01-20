package main

import (
	"fmt"
	"runtime"
	"os"
)

func main() {
    fmt.Println("OS:", runtime.GOOS)
    fmt.Println("Arch:", runtime.GOARCH)
    fmt.Println("CPUs:", runtime.NumCPU())
    fmt.Println("Go Version:", runtime.Version())
    fmt.Println("Home Dir:", os.UserHomeDir())
}