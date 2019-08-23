package main

import (
	"os"

	"github.com/bluele/slack"

	"github.com/youssefkaib/nister"
)

func main() {
	slackClient := slack.New("<insert_new_token_here>")
	product := os.Args
	data := nister.RecentCVES(product[1])
	for _, v := range data[0] {
		slackClient.ChatPostMessage("<insert_channel_name", v.CVE.MetaData.ID, nil)
	}
}
