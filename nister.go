package nister

import (
	"compress/gzip"
	"crypto/tls"
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
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	response, err := client.Get(url)
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
func RecentCVES(clientProduct string) map[int][]Item {
	cveData := ParseCVEReport(recentURL)
	cveReport := make(map[int][]Item)
	recentCVE := []Item{}
	modifiedCVE := []Item{}

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
						cveItem.Type = "latest_cve"
						recentCVE = append(recentCVE, cveItem)
						cveReport[0] = recentCVE
					}

				}
			}
			// list modified CVE
			if len(cveItem.CVE.Affects.Vendor.VendorData) != 0 {
				for _, k := range cveItem.CVE.Affects.Vendor.VendorData {

					k.VendorName = strings.ToLower(k.VendorName)
					clientProduct = strings.ToLower(clientProduct)

					if k.VendorName == clientProduct {
						cveItem.Type = "modified_cve"
						modifiedCVE = append(modifiedCVE, cveItem)
						cveReport[1] = modifiedCVE
					}
				}
			}
		}
	}

	return cveReport
}

// HighCVE checks today CVE with HIGH Severity
func HighCVE() []Item {
	cveData := ParseCVEReport(recentURL)
	recentCVE := []Item{}

	for _, cveItem := range cveData.CVEItems {
		publishedDate := strings.Split(cveItem.PublishedDate, "T")

		if cveItem.Impact.BaseMetricV2.Severity == "HIGH" && publishedDate[0] == todayDate[0] {
			recentCVE = append(recentCVE, cveItem)
		}
	}

	return recentCVE
}

// MediumCVE checks today CVE with Medium Severity
func MediumCVE() []Item {
	cveData := ParseCVEReport(recentURL)
	recentCVE := []Item{}

	for _, cveItem := range cveData.CVEItems {
		publishedDate := strings.Split(cveItem.PublishedDate, "T")

		if cveItem.Impact.BaseMetricV2.Severity == "MEDIUM" && publishedDate[0] == todayDate[0] {
			recentCVE = append(recentCVE, cveItem)
		}
	}

	return recentCVE
}

// LowCVE checks today's CVE with LOW Severity
func LowCVE() []Item {
	cveData := ParseCVEReport(recentURL)
	recentCVE := []Item{}

	for _, cveItem := range cveData.CVEItems {
		publishedDate := strings.Split(cveItem.PublishedDate, "T")

		if cveItem.Impact.BaseMetricV2.Severity == "LOW" && publishedDate[0] == todayDate[0] {
			recentCVE = append(recentCVE, cveItem)
		}
	}

	return recentCVE
}
