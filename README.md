# rfc8427

This is a Go implementation of the [RFC 8427](https://tools.ietf.org/html/rfc8427) specification for [miekg/dns](https://github.com/miekg/dns) objects.

## Usage

The following example shows how to use the library to marshal a DNS response to JSON.

```go
package main

import (
	"fmt"
	
	"github.com/miekg/dns"
	"github.com/tired-engineer/rfc8427"
)

func main() {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	msg.Id = 1234
	msg.RecursionDesired = true

	cl := new(dns.Client)
	resp, _, err := cl.Exchange(msg, "1.1.1.1:53")
	if err != nil {
		panic(err)
	}

	json, err := rfc8427.Marshal(resp)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(json))
}
```

It produces the following result (formatted for readability):
```json
{
	"ID": 1234,
	"QR": 1,
	"Opcode": 0,
	"AA": 0,
	"TC": 0,
	"RD": 1,
	"RA": 1,
	"AD": 0,
	"CD": 0,
	"RCODE": 0,
	"QDCOUNT": 1,
	"ANCOUNT": 6,
	"NSCOUNT": 0,
	"ARCOUNT": 0,
	"QNAME": "example.com",
	"QTYPE": 1,
	"QCLASS": 1,
	"questionRRs": [
		{
			"NAME": "example.com",
			"TYPE": 1,
			"CLASS": 1
		}
	],
	"answerRRs": [
		{
			"NAME": "example.com",
			"TYPE": 1,
			"CLASS": 1,
			"TTL": 167,
			"RDLENGTH": 4,
			"RDATAHEX": "600780c6",
			"rdataA": "96.7.128.198"
		},
		{
			"NAME": "example.com",
			"TYPE": 1,
			"CLASS": 1,
			"TTL": 167,
			"RDLENGTH": 4,
			"RDATAHEX": "17d7008a",
			"rdataA": "23.215.0.138"
		},
		{
			"NAME": "example.com",
			"TYPE": 1,
			"CLASS": 1,
			"TTL": 167,
			"RDLENGTH": 4,
			"RDATAHEX": "17d70088",
			"rdataA": "23.215.0.136"
		},
		{
			"NAME": "example.com",
			"TYPE": 1,
			"CLASS": 1,
			"TTL": 167,
			"RDLENGTH": 4,
			"RDATAHEX": "17c0e450",
			"rdataA": "23.192.228.80"
		},
		{
			"NAME": "example.com",
			"TYPE": 1,
			"CLASS": 1,
			"TTL": 167,
			"RDLENGTH": 4,
			"RDATAHEX": "17c0e454",
			"rdataA": "23.192.228.84"
		},
		{
			"NAME": "example.com",
			"TYPE": 1,
			"CLASS": 1,
			"TTL": 167,
			"RDLENGTH": 4,
			"RDATAHEX": "600780af",
			"rdataA": "96.7.128.175"
		}
	]
}
```