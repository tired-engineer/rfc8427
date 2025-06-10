# rfc8427

This is a Go implementation of the [RFC 8427](https://tools.ietf.org/html/rfc8427) specification for [miekg/dns](https://github.com/miekg/dns) objects.

## Usage

```go
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
	msg.Response = true
	msg.Authoritative = true

	cl := new(dns.Client)
	resp, _, err := cl.Exchange(msg, "8.8.8.8:53")
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