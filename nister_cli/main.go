package main

import (
	"fmt"
	"os"

	"github.com/youssefkaib/nister"
)

func main() {
	products := os.Args

	// Parsed CVE Data
	data := nister.ParseCVEReport()

	report := nister.ProductChecker(data, products)

	fmt.Println(report)
}
