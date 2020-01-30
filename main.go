package main

import (
	"fmt"
	"os"
	"time"
)

const sa = `<SA JSON KEY HERE>`

const targetAudience = "<TARGEY AUDIENCE HERE>"

func main() {
	s, err := MakeJWTTokenFromServiceAccountJSON(sa)
	if err != nil {
		panic(err)
	}
	tok, err := s.GetToken(time.Second*60, map[string]interface{}{"target_audience": targetAudience})
	if err != nil {
		panic(err)
	}
	fmt.Printf("token %v", tok.Token())
	os.Exit(0)
}
