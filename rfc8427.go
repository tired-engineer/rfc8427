package rfc8427

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	goccyJson "github.com/goccy/go-json"
)

// RFC8427Message represents a DNS message in RFC 8427 JSON format.
// See RFC 8427, Section 2.1.
type RFC8427Message struct {
	ID               *uint16                   `json:"ID,omitempty"`
	QR               *int                      `json:"QR,omitempty"` // Represent bool as int (0 or 1) as per RFC for some fields
	Opcode           *int                      `json:"Opcode,omitempty"`
	AA               *int                      `json:"AA,omitempty"`
	TC               *int                      `json:"TC,omitempty"`
	RD               *int                      `json:"RD,omitempty"`
	RA               *int                      `json:"RA,omitempty"`
	AD               *int                      `json:"AD,omitempty"`
	CD               *int                      `json:"CD,omitempty"`
	RCODE            *int                      `json:"RCODE,omitempty"`
	QDCOUNT          *uint16                   `json:"QDCOUNT,omitempty"`
	ANCOUNT          *uint16                   `json:"ANCOUNT,omitempty"`
	NSCOUNT          *uint16                   `json:"NSCOUNT,omitempty"`
	ARCOUNT          *uint16                   `json:"ARCOUNT,omitempty"`
	QNAME            *string                   `json:"QNAME,omitempty"`
	QTYPE            *uint16                   `json:"QTYPE,omitempty"`
	QCLASS           *uint16                   `json:"QCLASS,omitempty"`
	QuestionRRs      []RFC8427ResourceRecord `json:"questionRRs,omitempty"`
	AnswerRRs        []RFC8427ResourceRecord `json:"answerRRs,omitempty"`
	AuthorityRRs     []RFC8427ResourceRecord `json:"authorityRRs,omitempty"`
	AdditionalRRs    []RFC8427ResourceRecord `json:"additionalRRs,omitempty"`
	MessageOctetsHEX *string                   `json:"messageOctetsHEX,omitempty"` // Section 2.4
	HeaderOctetsHEX  *string                   `json:"headerOctetsHEX,omitempty"`  // Section 2.4
	// Other fields from Section 2.1 like QTYPEname, QCLASSname, compressedQNAME can be added as needed.
	// Additional fields from Section 2.5 like dateString, dateSeconds, comment can also be added.
}

// RFC8427ResourceRecord represents a DNS resource record in RFC 8427 JSON format.
// See RFC 8427, Section 2.2.
type RFC8427ResourceRecord struct {
	NAME     *string `json:"NAME,omitempty"`
	TYPE     *uint16 `json:"TYPE,omitempty"`
	CLASS    *uint16 `json:"CLASS,omitempty"`
	TTL      *int32  `json:"TTL,omitempty"` // TTL can be large, int32 is appropriate
	RDLENGTH *uint16 `json:"RDLENGTH,omitempty"`
	RDATAHEX *string `json:"RDATAHEX,omitempty"` // Hex-encoded RDATA

	// Specific RDATA field members from Section 2.3
	RdataA      *string `json:"rdataA,omitempty"`
	RdataAAAA   *string `json:"rdataAAAA,omitempty"`
	RdataCNAME  *string `json:"rdataCNAME,omitempty"`
	RdataDNAME  *string `json:"rdataDNAME,omitempty"`
	RdataNS     *string `json:"rdataNS,omitempty"`
	RdataPTR    *string `json:"rdataPTR,omitempty"`
	RdataTXT    *string `json:"rdataTXT,omitempty"`
	// Other rdata types like rdataMX, rdataSOA, etc., will be handled via RDATAHEX or specific structs if complex.

	// rrSet from Section 2.2 (can be a list of objects with RDLENGTH and RDATAHEX)
	// For simplicity, we'll primarily use RDATAHEX and specific rdata fields for now.
	// If rrSet is strictly needed, its structure would be: 
	// RRSet []struct { RDLENGTH *uint16 `json:"RDLENGTH,omitempty"`; RDATAHEX *string `json:"RDATAHEX,omitempty"` } `json:"rrSet,omitempty"`
}


// Marshal serializes a DNS message to RFC 8427 JSON format.
func Marshal(msg *dns.Msg) ([]byte, error) {
	if msg == nil {
		return nil, fmt.Errorf("input dns.Msg is nil")
	}

	qdcount := uint16(len(msg.Question))
	ancount := uint16(len(msg.Answer))
	nscount := uint16(len(msg.Ns))
	arcount := uint16(len(msg.Extra))
	rfcMsg := RFC8427Message{
		ID:      &msg.Id,
		Opcode:  &msg.Opcode,
		RCODE:   &msg.Rcode,
		QDCOUNT: &qdcount,
		ANCOUNT: &ancount,
		NSCOUNT: &nscount,
		ARCOUNT: &arcount,
	}

	// Helper function to convert bool to *int (0 or 1)
	boolToIntPtr := func(b bool) *int {
		val := 0
		if b {
			val = 1
		}
		return &val
	}

	rfcMsg.QR = boolToIntPtr(msg.Response) // QR is true if it's a response
	rfcMsg.AA = boolToIntPtr(msg.Authoritative)
	rfcMsg.TC = boolToIntPtr(msg.Truncated)
	rfcMsg.RD = boolToIntPtr(msg.RecursionDesired)
	rfcMsg.RA = boolToIntPtr(msg.RecursionAvailable)
	rfcMsg.AD = boolToIntPtr(msg.AuthenticatedData)
	rfcMsg.CD = boolToIntPtr(msg.CheckingDisabled)

	if len(msg.Question) > 0 {
		q := msg.Question[0]
		qname := strings.TrimSuffix(q.Name, ".") // RFC8427 QNAME usually doesn't have trailing dot
		rfcMsg.QNAME = &qname
		rfcMsg.QTYPE = &q.Qtype
		rfcMsg.QCLASS = &q.Qclass

		rfcMsg.QuestionRRs = make([]RFC8427ResourceRecord, len(msg.Question))
		for i, question := range msg.Question {
			rfcMsg.QuestionRRs[i] = convertQuestionToRFC8427RR(question)
		}
	}

	rfcMsg.AnswerRRs = convertRRs(msg.Answer)
	rfcMsg.AuthorityRRs = convertRRs(msg.Ns)
	rfcMsg.AdditionalRRs = convertRRs(msg.Extra)

	return goccyJson.Marshal(rfcMsg)
}

func convertRRs(rrs []dns.RR) []RFC8427ResourceRecord {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]RFC8427ResourceRecord, len(rrs))
	for i, rr := range rrs {
		out[i] = convertRRToRFC8427RR(rr)
	}
	return out
}

// convertRRToRFC8427RR converts a miekg/dns.RR to an RFC8427ResourceRecord.
func convertRRToRFC8427RR(rr dns.RR) RFC8427ResourceRecord {
	hdr := rr.Header()
	name := strings.TrimSuffix(hdr.Name, ".")
	rfcRR := RFC8427ResourceRecord{
		NAME:  &name,
		TYPE:  &hdr.Rrtype,
		CLASS: &hdr.Class,
		TTL:   ptrTo(int32(hdr.Ttl)),
	}

	// RDLENGTH and RDATAHEX are primary ways to represent RDATA.
	// For specific types, we can populate the rdata<TYPE> fields.
	// This requires a type switch on `rr`.
	// For now, let's focus on RDATAHEX and common types.

	// To get RDATAHEX, we need to pack the RR (excluding header) and hex encode it.
	// This is a bit tricky as miekg/dns doesn't directly expose RDATA bytes easily for all types.
	// A simpler approach for RDATAHEX for now might be to marshal the specific RR type data.
	// For a full RDATAHEX, one might need to pack the RR into a buffer and extract RDATA.

	// Placeholder for RDLENGTH and RDATAHEX - will require more detailed handling
	// rdLength := uint16(0) // Calculate actual RDLENGTH
	// rfcRR.RDLENGTH = &rdLength
	// rdataHex := "" // Calculate actual RDATAHEX
	// rfcRR.RDATAHEX = &rdataHex

	switch r := rr.(type) {
	case *dns.A:
		ipStr := r.A.String()
		rfcRR.RdataA = &ipStr
		rdBytes := []byte(r.A)
		rdl := uint16(len(rdBytes))
		rfcRR.RDLENGTH = &rdl
		rfcRR.RDATAHEX = ptrTo(hex.EncodeToString(rdBytes))
	case *dns.AAAA:
		ipStr := r.AAAA.String()
		rfcRR.RdataAAAA = &ipStr
		rdBytes := []byte(r.AAAA)
		rdl := uint16(len(rdBytes))
		rfcRR.RDLENGTH = &rdl
		rfcRR.RDATAHEX = ptrTo(hex.EncodeToString(rdBytes))
	case *dns.CNAME:
		// RFC specifies CNAME, DNAME, NS, PTR values are domain names.
		// miekg/dns stores them with a trailing dot, RFC8427 examples often don't for these specific fields.
		cname := strings.TrimSuffix(r.Target, ".")
		rfcRR.RdataCNAME = &cname
		// For RDATAHEX of CNAME, we need to pack the domain name.
		// This is complex. For now, we'll rely on the specific field.
	case *dns.DNAME:
		dname := strings.TrimSuffix(r.Target, ".")
		rfcRR.RdataDNAME = &dname
	case *dns.NS:
		ns := strings.TrimSuffix(r.Ns, ".")
		rfcRR.RdataNS = &ns
	case *dns.PTR:
		ptr := strings.TrimSuffix(r.Ptr, ".")
		rfcRR.RdataPTR = &ptr
	case *dns.RFC3597:
		rdBytes := []byte(r.Rdata)
		rdl := uint16(len(rdBytes))
		rfcRR.RDLENGTH = &rdl
		rfcRR.RDATAHEX = ptrTo(hex.EncodeToString(rdBytes))
	case *dns.TXT:
		// RFC8427 rdataTXT is a single string. Per the RFC, multiple strings are concatenated.
		txt := strings.Join(r.Txt, "")
		rfcRR.RdataTXT = &txt

		// To allow for a perfect round-trip, we also generate RDATAHEX,
		// which preserves the separate strings in wire format. RDATAHEX is authoritative.
		var rdBytes []byte
		for _, s := range r.Txt {
			if len(s) > 255 {
				// This is an invalid TXT string, but we should handle it gracefully.
				// For now, let's assume valid input.
				s = s[:255]
			}
			rdBytes = append(rdBytes, byte(len(s)))
			rdBytes = append(rdBytes, []byte(s)...)
		}
		rdl := uint16(len(rdBytes))
		rfcRR.RDLENGTH = &rdl
		rfcRR.RDATAHEX = ptrTo(hex.EncodeToString(rdBytes))
	default:
		// For unknown types, or types not specifically handled, try to generate RDATAHEX.
		// This is the most complex part. dns.PackRR can pack the whole RR.
		// We need to extract just the RDATA part.
		// A common way is to pack the RR, then strip the header, but header length can vary (compression).
		// For now, we'll leave RDATAHEX blank for unhandled types, to be implemented later.
		// A proper implementation would involve packing the RR and then extracting the RDATA based on RDLENGTH.
		// For example, using a temporary buffer:
		// buf := make([]byte, 512) // Or a more appropriate size
		// off, err := dns.PackRR(rr, buf, 0, nil, false)
		// if err == nil {
		// 	 headerLen := // ... calculate actual header length (can be tricky due to compression)
		// 	 rdata := buf[headerLen:off]
		// 	 rfcRR.RDATAHEX = ptrTo(hex.EncodeToString(rdata))
		// 	 rdl := uint16(len(rdata))
		// 	 rfcRR.RDLENGTH = &rdl
		// }
		// This is a simplification and might not be robust for all cases.
		// The miekg/dns library does not provide a direct `GetRdata()` method that returns raw bytes.
		// One might need to use `rr.String()` and parse, or use a more involved packing mechanism.
		// The most reliable way to get RDATA bytes is to pack the RR and then extract the RDATA part.
		// However, `dns.PackRR` packs the *entire* RR. The header part would need to be skipped.
		// The length of the packed header isn't fixed due to name compression.
		// A simpler, though less efficient way for some types, is to use their String() representation
		// if it matches the wire format for RDATA, but this is not generally true.
		
		// For now, if we can't get specific RDATA, we'll leave RDATAHEX nil.
		// A full implementation would require careful handling of each RR type or a generic RDATA packer.
		// Let's try a basic RDATAHEX for SOA as an example of more complex data.
		// if soa, ok := rr.(*dns.SOA); ok { // Removed unused soa variable and block
		// 	 // SOA RDATA: MNAME, RNAME, SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM
		// 	 // All need to be packed. This is non-trivial to do manually here.
		// 	 // Relying on a generic RDATAHEX for SOA is better if available.
		// }
	}

	return rfcRR
}

// convertQuestionToRFC8427RR converts a miekg/dns.Question to an RFC8427ResourceRecord.
// As per RFC 8427, Section 2.2: "A Question section can be expressed as a resource record.
// When doing so, the TTL, RDLENGTH, and RDATA members make no sense."
func convertQuestionToRFC8427RR(q dns.Question) RFC8427ResourceRecord {
	name := strings.TrimSuffix(q.Name, ".")
	return RFC8427ResourceRecord{
		NAME:  &name,
		TYPE:  &q.Qtype,
		CLASS: &q.Qclass,
		// TTL, RDLENGTH, RDATAHEX are omitted for questions
	}
}

// ptrTo returns a pointer to the given value.
func ptrTo[T any](v T) *T {
	return &v
}

// Unmarshal parses RFC 8427 JSON into a DNS message.
func Unmarshal(data []byte, msg *dns.Msg) error {
	// Implementation to follow
	var rfcMsg RFC8427Message
	if err := goccyJson.Unmarshal(data, &rfcMsg); err != nil {
		return fmt.Errorf("error unmarshaling JSON: %w", err)
	}

	if msg == nil {
		// This case should ideally not happen if msg is expected to be populated.
		// If msg can be nil and should be allocated, this needs different handling.
		return fmt.Errorf("output dns.Msg is nil")
	}

	// Reset message to a clean state
	*msg = dns.Msg{}

	if rfcMsg.ID != nil {
		msg.Id = *rfcMsg.ID
	}
	if rfcMsg.Opcode != nil {
		msg.Opcode = *rfcMsg.Opcode
	}
	if rfcMsg.RCODE != nil {
		msg.Rcode = *rfcMsg.RCODE
	}

	intPtrToBool := func(i *int) bool {
		if i == nil {
			return false // Default to false if not present
		}
		return *i == 1
	}

	msg.Response = intPtrToBool(rfcMsg.QR)
	msg.Authoritative = intPtrToBool(rfcMsg.AA)
	msg.Truncated = intPtrToBool(rfcMsg.TC)
	msg.RecursionDesired = intPtrToBool(rfcMsg.RD)
	msg.RecursionAvailable = intPtrToBool(rfcMsg.RA)
	msg.AuthenticatedData = intPtrToBool(rfcMsg.AD)
	msg.CheckingDisabled = intPtrToBool(rfcMsg.CD)

	// QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT from JSON are not directly set on dns.Msg.
	// They are implicit from the lengths of Question, Answer, Ns, Extra slices.
	// These can be used for validation if needed.
	// if rfcMsg.QDCOUNT != nil {
	// 	 // msg.Hdr.Qdcount = *rfcMsg.QDCOUNT // Incorrect access
	// }
	// if rfcMsg.ANCOUNT != nil {
	// 	 // msg.Hdr.Ancount = *rfcMsg.ANCOUNT // Incorrect access
	// }
	// if rfcMsg.NSCOUNT != nil {
	// 	 // msg.Hdr.Nscount = *rfcMsg.NSCOUNT // Incorrect access
	// }
	// if rfcMsg.ARCOUNT != nil {
	// 	 // msg.Hdr.Arcount = *rfcMsg.ARCOUNT // Incorrect access
	// }

	if len(rfcMsg.QuestionRRs) > 0 {
		msg.Question = make([]dns.Question, len(rfcMsg.QuestionRRs))
		for i, rfcRR := range rfcMsg.QuestionRRs {
			q := dns.Question{}
			if rfcRR.NAME != nil {
				q.Name = dns.Fqdn(*rfcRR.NAME)
			}
			if rfcRR.TYPE != nil {
				q.Qtype = *rfcRR.TYPE
			}
			if rfcRR.CLASS != nil {
				q.Qclass = *rfcRR.CLASS
			}
			msg.Question[i] = q
		}
	} else if rfcMsg.QNAME != nil && rfcMsg.QTYPE != nil && rfcMsg.QCLASS != nil { // Fallback to top-level QNAME/QTYPE/QCLASS
		msg.Question = make([]dns.Question, 1)
		msg.Question[0] = dns.Question{
			Name:   dns.Fqdn(*rfcMsg.QNAME),
			Qtype:  *rfcMsg.QTYPE,
			Qclass: *rfcMsg.QCLASS,
		}
		// msg.Hdr.Qdcount is implicit
	}

	var err error
	msg.Answer, err = convertRFC8427RRsToDNSRRs(rfcMsg.AnswerRRs)
	if err != nil {
		return fmt.Errorf("error converting Answer RRs: %w", err)
	}
	msg.Ns, err = convertRFC8427RRsToDNSRRs(rfcMsg.AuthorityRRs)
	if err != nil {
		return fmt.Errorf("error converting Authority RRs: %w", err)
	}
	msg.Extra, err = convertRFC8427RRsToDNSRRs(rfcMsg.AdditionalRRs)
	if err != nil {
		return fmt.Errorf("error converting Additional RRs: %w", err)
	}

	// Counts like Ancount, Nscount, Arcount are implicit in dns.Msg from slice lengths.
	// The JSON counts can be used for validation if desired, but not set directly here.
	return nil
}

func convertRFC8427RRsToDNSRRs(rfcRRs []RFC8427ResourceRecord) ([]dns.RR, error) {
	if len(rfcRRs) == 0 {
		return nil, nil
	}
	dnsRRs := make([]dns.RR, 0, len(rfcRRs))
	for _, rfcRR := range rfcRRs {
		if rfcRR.NAME == nil || rfcRR.TYPE == nil || rfcRR.CLASS == nil {
			return nil, fmt.Errorf("RR missing NAME, TYPE, or CLASS: %+v", rfcRR)
		}

		hdr := dns.RR_Header{
			Name:   dns.Fqdn(*rfcRR.NAME),
			Rrtype: *rfcRR.TYPE,
			Class:  *rfcRR.CLASS,
		}
		if rfcRR.TTL != nil {
			hdr.Ttl = uint32(*rfcRR.TTL)
		}
		// RDLENGTH is typically derived when packing, or from RDATAHEX length

		rrFunc, ok := dns.TypeToRR[*rfcRR.TYPE] // Corrected map access
		if !ok {
			// If it's an unknown type to miekg/dns
			if rfcRR.RDATAHEX != nil {
				rdataBytes, err := hex.DecodeString(*rfcRR.RDATAHEX)
				if err != nil {
					return nil, fmt.Errorf("invalid RDATAHEX for %s type %d: %w", *rfcRR.NAME, *rfcRR.TYPE, err)
				}
				hdr.Rdlength = uint16(len(rdataBytes)) // Ensure Rdlength is set in the header
				rfc3597RR := &dns.RFC3597{Hdr: hdr, Rdata: string(rdataBytes)}
				dnsRRs = append(dnsRRs, rfc3597RR)
				continue
			}
			return nil, fmt.Errorf("unsupported RR type %d with no RDATAHEX", *rfcRR.TYPE)
		}
		dnsRR := rrFunc() // Call the constructor function
		if dnsRR == nil { // Should not happen if rrFunc is valid and returns non-nil
			// If it's an unknown type, we might try to create a dns.PrivateRR or similar
			// For now, we'll skip unknown types or return an error if strict parsing is needed
			// If RDATAHEX is present, we could use it with a generic RR type.
			if rfcRR.RDATAHEX != nil {
				rdataBytes, err := hex.DecodeString(*rfcRR.RDATAHEX)
				if err != nil {
					return nil, fmt.Errorf("invalid RDATAHEX for %s type %d: %w", *rfcRR.NAME, *rfcRR.TYPE, err)
				}
				hdr.Rdlength = uint16(len(rdataBytes)) // Ensure Rdlength is set in the header
				rfc3597RR := &dns.RFC3597{Hdr: hdr, Rdata: string(rdataBytes)}
				dnsRRs = append(dnsRRs, rfc3597RR)
				continue
			}
			return nil, fmt.Errorf("unsupported RR type %d with no RDATAHEX", *rfcRR.TYPE)
		}

		// Set the header for the concrete RR type
		*dnsRR.Header() = hdr

		switch r := dnsRR.(type) {
		case *dns.A:
			if rfcRR.RdataA != nil {
				r.A = net.ParseIP(*rfcRR.RdataA)
				if r.A == nil {
					return nil, fmt.Errorf("invalid A record IP: %s", *rfcRR.RdataA)
				}
				if r.A.To4() != nil {
					// This is a 4-byte representation, convert to 16-byte for consistency.
					r.A = r.A.To16()
				}
			} else if rfcRR.RDATAHEX != nil {
				// Parse from RDATAHEX
				b, err := hex.DecodeString(*rfcRR.RDATAHEX)
				if err != nil || len(b) != net.IPv4len {
					return nil, fmt.Errorf("invalid RDATAHEX for A record: %s", *rfcRR.RDATAHEX)
				}
				r.A = net.IP(b)
			} else {
				return nil, fmt.Errorf("A record missing rdataA or RDATAHEX")
			}
		case *dns.AAAA:
			if rfcRR.RdataAAAA != nil {
				r.AAAA = net.ParseIP(*rfcRR.RdataAAAA)
				if r.AAAA == nil {
					return nil, fmt.Errorf("invalid AAAA record IP: %s", *rfcRR.RdataAAAA)
				}
				r.AAAA = r.AAAA.To16() // Ensure it's IPv6
			} else if rfcRR.RDATAHEX != nil {
				b, err := hex.DecodeString(*rfcRR.RDATAHEX)
				if err != nil || len(b) != net.IPv6len {
					return nil, fmt.Errorf("invalid RDATAHEX for AAAA record: %s", *rfcRR.RDATAHEX)
				}
				r.AAAA = net.IP(b)
			} else {
				return nil, fmt.Errorf("AAAA record missing rdataAAAA or RDATAHEX")
			}
		case *dns.CNAME:
			if rfcRR.RdataCNAME != nil {
				r.Target = dns.Fqdn(*rfcRR.RdataCNAME)
			} else {
				return nil, fmt.Errorf("CNAME record missing rdataCNAME")
			}
		case *dns.DNAME:
			if rfcRR.RdataDNAME != nil {
				r.Target = dns.Fqdn(*rfcRR.RdataDNAME)
			} else {
				return nil, fmt.Errorf("DNAME record missing rdataDNAME")
			}
		case *dns.NS:
			if rfcRR.RdataNS != nil {
				r.Ns = dns.Fqdn(*rfcRR.RdataNS)
			} else {
				return nil, fmt.Errorf("NS record missing rdataNS")
			}
		case *dns.PTR:
			if rfcRR.RdataPTR != nil {
				r.Ptr = dns.Fqdn(*rfcRR.RdataPTR)
			} else {
				return nil, fmt.Errorf("PTR record missing rdataPTR")
			}
		case *dns.TXT:
			// Per RFC 8427, if both RDATAHEX and rdataTXT are present, RDATAHEX is authoritative.
			if rfcRR.RDATAHEX != nil {
				rdataBytes, err := hex.DecodeString(*rfcRR.RDATAHEX)
				if err != nil {
					return nil, fmt.Errorf("invalid RDATAHEX for TXT: %w", err)
				}
				// Parse the wire format for TXT RDATA, which is a sequence of length-prefixed strings.
				idx := 0
				for idx < len(rdataBytes) {
					length := int(rdataBytes[idx])
					idx++
					if idx+length > len(rdataBytes) {
						return nil, fmt.Errorf("invalid TXT RDATA string length")
					}
					r.Txt = append(r.Txt, string(rdataBytes[idx:idx+length]))
					idx += length
				}
			} else if rfcRR.RdataTXT != nil {
				// Fallback to rdataTXT if RDATAHEX is not available.
				// This will result in a single string in the slice.
				r.Txt = []string{*rfcRR.RdataTXT}
			} else {
				return nil, fmt.Errorf("TXT record missing rdataTXT or RDATAHEX")
			}
		// Add more cases for other RR types (MX, SOA, SRV, etc.)
		// For types not specifically handled, if RDATAHEX was provided and parsed into a PrivateRR, it's already added.
		// If it's a known type but not handled here, it will be an empty RR, which is not ideal.
		// A full implementation needs to handle all common types or have a robust generic RDATAHEX -> specific type parser.
		default:
			// If we reached here, it's a known type by miekg/dns but not specifically handled above.
			// We must try to populate it from RDATAHEX if available.
			// This is for types known to miekg/dns but not having a specific case above (e.g., SOA, MX).
			if rfcRR.RDATAHEX != nil {
				// _, err := hex.DecodeString(*rfcRR.RDATAHEX) // Removed rdataBytes to avoid unused error for now
				// if err != nil {
				// 	 return nil, fmt.Errorf("invalid RDATAHEX for %s type %d: %w", *rfcRR.NAME, *rfcRR.TYPE, err)
				// }
				// RDATA parsing for these generic types from RDATAHEX into the specific dnsRR fields is complex and not yet implemented.
				// For now, the RR will be added with only its header populated if no specific RDATA fields were in the JSON.
				fmt.Printf("Warning: RR type %d (%s) has RDATAHEX, but no specific unmarshal logic implemented to parse it into RR fields. RR may be incomplete.\n", *rfcRR.TYPE, dns.TypeToString[*rfcRR.TYPE])
			} else {
				// No RDATAHEX and no specific handling for this known type.
				fmt.Printf("Warning: RR type %d (%s) has no RDATAHEX and no specific unmarshal handler. RR will be incomplete.\n", *rfcRR.TYPE, dns.TypeToString[*rfcRR.TYPE])
			}
		}
		dnsRRs = append(dnsRRs, dnsRR)
	}
	return dnsRRs, nil
}
