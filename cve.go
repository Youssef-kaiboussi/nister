package nister

// Data ...
type Data struct {
	DataType     string `json:"CVE_data_type"`
	DataFormat   string `json:"CVE_data_format"`
	DataVersion  string `json:"CVE_data_version"`
	NumberOfCVEs string `json:"CVE_data_numberOfCVEs"`
	Timestamp    string `json:"CVE_data_timestamp"`
	CVEItems     []Item `json:"CVE_Items"`
}

// Item ...
type Item struct {
	CVE struct {
		Type     string `json:"data_type"`
		Formart  string `json:"data_format"`
		Version  string `json:"data_version"`
		MetaData struct {
			ID       string `json:"id"`
			ASSIGNER string `json:"ASSIGNER"`
		} `json:"CVE_data_meta"`
		Affects struct {
			Vendor struct {
				VendorData []struct {
					VendorName string `json:"vendor_name"`
					Product    struct {
						ProductData []struct {
							ProductName string `json:"product_name"`
							Version     struct {
								VersionData []struct {
									VersionValue string `json:"version_value"`
								} `json:"version_data"`
							} `json:"version"`
						} `json:"product_data"`
					} `json:"product"`
				} `json:"vendor_data"`
			} `json:"vendor"`
		} `json:"affects"`
		References struct {
			ReferenceData []struct {
				URL       string `json:"url"`
				Name      string `json:"name"`
				Refsource string `json:"refsource"`
			} `json:"reference_data"`
		} `json:"references"`
		Description struct {
			DescriptionData []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"description_data"`
		} `json:"description"`
	} `json:"cve"`
	Impact struct {
		BaseMetricV2 struct {
			Severity                string  `json:"severity"`
			ExploitabilityScore     float64 `json:"exploitabilityScore"`
			ImpactScore             float64 `json:"impactScore"`
			ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
			ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
			ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
			UserInteractionRequired bool    `json:"userInteractionRequired"`
		} `json:"baseMetricV2"`
	} `json:"impact"`
	PublishedDate    string `json:"publishedDate"`
	LastModifiedDate string `json:"lastModifiedDate"`
}
