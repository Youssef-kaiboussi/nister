package main

import (
	"fmt"
	"os"

	"github.com/youssefkaib/nister"
)

func main() {

	newSearch := os.Args
	data := nister.SearchCVE(newSearch[1])

	for _, v := range data {
		for _, reference := range v.CVE.References.ReferenceData {
			fmt.Printf("References: %v \n", reference)
		}
	}

}
