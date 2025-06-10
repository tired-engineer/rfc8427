package rfc8427

import (
	"reflect"
	"sort"
	"testing"

	"github.com/miekg/dns"
)

// Helper to compare two dns.Msg objects
func msgEqual(t *testing.T, a, b *dns.Msg) bool {
	if a == nil || b == nil {
		return a == b
	}

	// Use a copy to avoid modifying the original slices
	aCopy := a.Copy()
	bCopy := b.Copy()

	// Compare header fields
	if aCopy.MsgHdr.Id != bCopy.MsgHdr.Id ||
		aCopy.MsgHdr.Response != bCopy.MsgHdr.Response ||
		aCopy.MsgHdr.Opcode != bCopy.MsgHdr.Opcode ||
		aCopy.MsgHdr.Authoritative != bCopy.MsgHdr.Authoritative ||
		aCopy.MsgHdr.Truncated != bCopy.MsgHdr.Truncated ||
		aCopy.MsgHdr.RecursionDesired != bCopy.MsgHdr.RecursionDesired ||
		aCopy.MsgHdr.RecursionAvailable != bCopy.MsgHdr.RecursionAvailable ||
		aCopy.MsgHdr.AuthenticatedData != bCopy.MsgHdr.AuthenticatedData ||
		aCopy.MsgHdr.CheckingDisabled != bCopy.MsgHdr.CheckingDisabled ||
		aCopy.MsgHdr.Rcode != bCopy.MsgHdr.Rcode {
		t.Errorf("Header mismatch:\nOriginal: %+v\nGot:      %+v", aCopy.MsgHdr, bCopy.MsgHdr)
		return false
	}

	// Compare question
	if !reflect.DeepEqual(aCopy.Question, bCopy.Question) {
		t.Errorf("Question mismatch:\nOriginal: %+v\nGot:      %+v", aCopy.Question, bCopy.Question)
		return false
	}

	// Compare RR sections (order-insensitive)
	sortRRs(aCopy.Answer)
	sortRRs(bCopy.Answer)
	sortRRs(aCopy.Ns)
	sortRRs(bCopy.Ns)
	sortRRs(aCopy.Extra)
	sortRRs(bCopy.Extra)

		if !reflect.DeepEqual(aCopy.Answer, bCopy.Answer) {
		t.Errorf("Answer RR mismatch:\nOriginal: %v\nGot:      %v", aCopy.Answer, bCopy.Answer)
		return false
	}
	if !reflect.DeepEqual(aCopy.Ns, bCopy.Ns) {
		t.Errorf("Authority RR mismatch:\nOriginal: %v\nGot:      %v", aCopy.Ns, bCopy.Ns)
		return false
	}
	if !reflect.DeepEqual(aCopy.Extra, bCopy.Extra) {
		t.Errorf("Additional RR mismatch:\nOriginal: %v\nGot:      %v", aCopy.Extra, bCopy.Extra)
		return false
	}

	return true
}

// Helper function to sort RRs for comparison
func sortRRs(rrs []dns.RR) {
	sort.Slice(rrs, func(i, j int) bool {
		return rrs[i].String() < rrs[j].String()
	})
}

func TestRoundTrip(t *testing.T) {
	// 1. Create a sample dns.Msg
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	msg.Id = 1234
	msg.RecursionDesired = true
	msg.Response = true
	msg.Authoritative = true

	a, _ := dns.NewRR("example.com. 3600 IN A 192.0.2.1")
	aaaa, _ := dns.NewRR("example.com. 3600 IN AAAA 2001:db8::1")
	cname, _ := dns.NewRR("www.example.com. 3600 IN CNAME example.com.")
	txt, _ := dns.NewRR(`example.com. 3600 IN TXT "hello world" "another string"`)

	// Create an "unknown" type RR for the RFC3597 test case
	unknownRR := &dns.RFC3597{
		Hdr:  dns.RR_Header{Name: dns.Fqdn("example.com"), Rrtype: 9999, Class: dns.ClassINET, Ttl: 3600, Rdlength: 4},
		Rdata: "\x01\x02\x03\x04",
	}

	msg.Answer = []dns.RR{a, aaaa, cname, txt, unknownRR}
	msg.Ns = []dns.RR{
		&dns.NS{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 86400}, Ns: "ns1.example.com."},
	}

	// 2. Marshal to JSON
	jsonData, err := Marshal(msg)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	// 3. Unmarshal back to dns.Msg
	unmarshaledMsg := new(dns.Msg)
	err = Unmarshal(jsonData, unmarshaledMsg)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v, json data was:\n%s", err, string(jsonData))
	}

	// 4. Compare the original and unmarshaled messages
	if !msgEqual(t, msg, unmarshaledMsg) {
		t.Errorf("Round-tripped message does not match original.")
		t.Logf("Original:\n%s\n", msg.String())
		t.Logf("Unmarshaled:\n%s\n", unmarshaledMsg.String())
		t.Logf("JSON data:\n%s\n", string(jsonData))
	}
}
