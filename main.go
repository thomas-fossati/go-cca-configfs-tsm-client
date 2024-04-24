package main

import (
	"fmt"
	"log"

	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	"github.com/google/go-configfs-tsm/report"
	"github.com/veraison/ccatoken"
)

func main() {
	req := &report.Request{
		InBlob: []byte("random-challenge"),
	}

	res, err := linuxtsm.GetReport(req)
	if err != nil {
		log.Fatalf("GetReport failed: %s", err)
	}

	e := ccatoken.Evidence{}

	err = e.FromCBOR(res.OutBlob)
	if err != nil {
		log.Fatalf("CCA token CBOR decoding failed: %s", err)
	}

	b, err := e.MarshalJSON()
	if err != nil {
		log.Fatalf("CCA token JSON marshalling failed: %s", err)
	}

	fmt.Println(string(b))
}
