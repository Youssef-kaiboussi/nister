package nister

import (
	"compress/gzip"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"
)

var todayDate = strings.Split(time.Now().Format(time.RFC3339), "T")
var recentURL = "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-recent.json.gz"

// ParseCVEReport ...
func ParseCVEReport(url string) Data {
	response, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}

	gr, err := gzip.NewReader(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	defer gr.Close()

	body, err := ioutil.ReadAll(gr)
	if err != nil {
		log.Fatal(err)
	}

	d := Data{}
	err = json.Unmarshal(body, &d)
	if err != nil {
		log.Fatal(err)
	}

	return d
}

// RecentCVES function call retievers today's published and modified CVE by passing an array of products
func RecentCVES(clientProducts []string) map[string][]Item {
	cveData := ParseCVEReport(recentURL)
	cveReport := make(map[string][]Item)
	recentCVE := []Item{}
	modifiedCVE := []Item{}

	for _, clientProduct := range clientProducts {
		for _, cveItem := range cveData.CVEItems {

			publishedDate := strings.Split(cveItem.PublishedDate, "T")
			// check most recent cve when vendor's name not present on report
			if len(cveItem.CVE.Affects.Vendor.VendorData) == 0 && publishedDate[0] == todayDate[0] {
				for _, j := range cveItem.CVE.Description.DescriptionData {

					desc := strings.Split(j.Value, " ")
					for _, k := range desc {

						k = strings.ToLower(k)
						clientProduct = strings.ToLower(clientProduct)

						var s = []string{}
						if k == clientProduct {
							s = append(s, k)
						}
						// verify product present in description without duplicate CVE
						if k == clientProduct && len(s) != 0 {
							recentCVE = append(recentCVE, cveItem)
							cveReport["recent_CVE"] = recentCVE
						}
					}
				}
			}
			// list modified CVE
			if len(cveItem.CVE.Affects.Vendor.VendorData) != 0 {
				for _, k := range cveItem.CVE.Affects.Vendor.VendorData {

					k.VendorName = strings.ToLower(k.VendorName)
					clientProduct = strings.ToLower(clientProduct)

					if k.VendorName == clientProduct {

						modifiedCVE = append(modifiedCVE, cveItem)
						cveReport["modified_CVE"] = modifiedCVE
					}
				}
			}
		}
	}

	return cveReport
}
