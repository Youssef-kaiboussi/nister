package main

import (
	"fmt"

	"github.com/youssefkaib/nister"
)

func main() {
	// product := os.Args
	data := nister.RecentCVES("python")
	for _, v := range data[0] {
		fmt.Println("ID: ", v.CVE.MetaData.ID)
	}
}
