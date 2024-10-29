package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

func monitorConsoleLog(ctx context.Context) {
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		if ev, ok := ev.(*runtime.EventConsoleAPICalled); ok {
			for _, arg := range ev.Args {
				log.Printf("console log: %s", arg.Value)
			}
		}
	})
}

func main() {
	var ips string
	var ipList []string
	var port int
	var timeout int

	flag.StringVar(&ips, "ips", "", "Space separated list of IPs")
	flag.IntVar(&port, "port", 443, "Port number")
	flag.IntVar(&timeout, "timeout", 5, "Timeout in seconds")
	flag.Parse()

	if ips == "" {
		log.Fatal("Please provide IPs")
	}
	ipList = strings.Split(ips, " ")

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("ignore-certificate-errors", true),
	)
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	for _, ip := range ipList {
		ctx, ctxCancel := chromedp.NewContext(allocCtx)
		ctx, timeoutCancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)

		monitorConsoleLog(ctx)

		var status string

		err := chromedp.Run(ctx,
			chromedp.Navigate(fmt.Sprintf("https://%s:%d", ip, port)),
			chromedp.WaitVisible("#status"),
			chromedp.WaitVisible("#status-done"),
			chromedp.Text("#status-done", &status),
		)

		timeoutCancel()

		if err != nil {
			log.Fatal(err)
		}
		log.Printf("status: %s", status)
		ctxCancel()
	}

}
