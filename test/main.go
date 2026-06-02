package main

import (
	"context"
	"net"
	"net/http"
	"time"
)

func getHTTPClients() (*http.Client, *http.Client) {
	dialer := net.Dialer{
		FallbackDelay: -1,
	}
	tp4 := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", addr)
		},
		MaxIdleConns:      1,
		DisableKeepAlives: true,
	}
	tp6 := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp6", addr)
		},
		MaxIdleConns:      1,
		DisableKeepAlives: true,
	}

	client4 := &http.Client{
		Transport: tp4,
		Timeout:   3 * time.Second,
	}
	client6 := &http.Client{
		Transport: tp6,
		Timeout:   3 * time.Second,
	}

	return client4, client6
}

func makeHTTPReqs(client4, client6 *http.Client, addr string) error {
	if client4 != nil {
		resp, err := client4.Get(addr)
		if err != nil {
			return err
		}
		resp.Body.Close()
	}

	if false && client6 != nil {
		resp, err := client6.Get(addr)
		if err != nil {
			return err
		}
		resp.Body.Close()
	}

	return nil
}

func main() {
	client4, client6 := getHTTPClients()

	err := makeHTTPReqs(client4, client6, "https://google.com")
	if err != nil {
		panic(err)
	}
}


0000   58 d6 1f 2a 87 94 c4 62 37 07 af 28 08 00 45 00
0010   00 43 06 9b 40 00 40 11 9c 17 0a 4e 3c f2 0a 4e
0020   46 6a bc da 00 35 00 2f 98 38 ee c3 01 00 00 01
0030   00 00 00 00 00 01 06 67 6f 6f 67 6c 65 03 63 6f
0040   6d 00 00 01 00 01 00 00 29 04 d0 00 00 00 00 00
0050   00


