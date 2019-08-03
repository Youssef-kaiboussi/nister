package main

import (
	"fmt"
	"os"

	"github.com/youssefkaib/nister"
)

func main() {
	products := os.Args

	report := nister.RecentCVES(products)

	fmt.Println(report)
}
