[Build Status]: https://travis-ci.org/ykaiboussi/nister
[Build Status Badge]:https://travis-ci.com/ykaiboussi/nister.svg?branch=master

# Nister

[![Build Status][Build Status Badge]][Build Status] [![Go Report Card](https://goreportcard.com/badge/github.com/ykaiboussi/nister)](https://goreportcard.com/report/github.com/ykaiboussi/nister)

Nister is a lightweight Go package that returns the most recent, modified [CVE](https://cve.mitre.org/) Per **Product or Programing Language** from [National Vulnerability Database](https://nvd.nist.gov/vuln/data-feeds) and HIGH, MEDIUM, LOW severities.

## Installation

```md
go get github.com/ykaiboussi/nister
```

### CLI Example

![](https://media.giphy.com/media/hvGbporNaP1xozXbxn/giphy.gif)

![nister_cli](https://github.com/ykaiboussi/nister/blob/master/images/nister_cli_example.png)

```go
package main

import (
    "fmt"
    "os"

    "github.com/ykaiboussi/nister"
)

func main() {
    product := os.Args
    data := nister.RecentCVES(product[1])
    for _, v := range data[0] {
        fmt.Println("ID: ", v.CVE.MetaData.ID)
    }
}

```

### Contributing

Pull requests, bug fixes, and new features are welcome!

1. Fork the repository
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -a -m 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request on GitHub
