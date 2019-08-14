package main

import (
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/youssefkaib/nister"
)

func main() {
	data := nister.RecentCVES("wordpress")

	for _, v := range data["recent_CVE"] {
		fmt.Printf("recent_CVE: %v \n", v.CVE.MetaData.ID)
	}

	spew.Dump("********************************")

	for _, v := range data["modified_CVE"] {
		fmt.Printf("Modified_CVE: %v", v.CVE.MetaData.ID)
	}
}
