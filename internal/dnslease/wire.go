// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package dnslease

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"golang.org/x/net/dns/dnsmessage"
)

func parseQuery(wire []byte) (dnsmessage.Message, error) {
	var message dnsmessage.Message
	if err := boundedWire(wire); err != nil {
		return message, err
	}
	if err := message.Unpack(wire); err != nil {
		return message, fmt.Errorf("invalid DNS query: %w", err)
	}
	if binary.BigEndian.Uint16(wire[2:4])&^uint16(0x0100) != 0 || len(message.Questions) != 1 || len(message.Answers) != 0 || len(message.Authorities) != 0 || len(message.Additionals) != 0 {
		return message, fmt.Errorf("only one ordinary DNS question is supported")
	}
	q := message.Questions[0]
	name := q.Name.String()
	if q.Class != dnsmessage.ClassINET || (q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeAAAA) || len(name) < 2 || !canonicalHostname(name[:len(name)-1]) || name[len(name)-1] != '.' {
		return message, fmt.Errorf("only canonical IN A/AAAA questions are supported")
	}
	canonical, err := message.Pack()
	if err != nil || !bytes.Equal(wire, canonical) {
		return message, fmt.Errorf("the question must use canonical uncompressed encoding")
	}
	return message, nil
}

// dnsmessage validates DNS names and resource bodies. This additional framing
// check rejects trailing bytes and forward compression pointers.
func boundedWire(wire []byte) error {
	if len(wire) < 12 || len(wire) > MaxWire {
		return fmt.Errorf("DNS message size is outside the target limit")
	}
	counts := [4]uint16{}
	for i := range counts {
		counts[i] = binary.BigEndian.Uint16(wire[4+i*2 : 6+i*2])
	}
	if counts[0] != 1 || int(counts[1])+int(counts[2])+int(counts[3]) > MaxAnswers {
		return fmt.Errorf("DNS section count exceeds the target limit")
	}
	offset := 12
	for section, count := range counts {
		for i := uint16(0); i < count; i++ {
			var err error
			offset, err = skipWireName(wire, offset)
			if err != nil {
				return err
			}
			if section == 0 {
				offset += 4
			} else {
				if offset+10 > len(wire) {
					return fmt.Errorf("short DNS resource header")
				}
				length := int(binary.BigEndian.Uint16(wire[offset+8 : offset+10]))
				if binary.BigEndian.Uint16(wire[offset:offset+2]) == uint16(dnsmessage.TypeCNAME) {
					next, err := skipWireName(wire, offset+10)
					if err != nil {
						return err
					}
					if next != offset+10+length {
						return fmt.Errorf("CNAME data length differs")
					}
				}
				offset += 10 + length
			}
			if offset > len(wire) {
				return fmt.Errorf("short DNS section")
			}
		}
	}
	if offset != len(wire) {
		return fmt.Errorf("DNS message has trailing bytes")
	}
	return nil
}

func skipWireName(wire []byte, offset int) (int, error) {
	for steps := 0; steps < 128; steps++ {
		if offset >= len(wire) {
			return 0, fmt.Errorf("short DNS name")
		}
		length := int(wire[offset])
		if length&0xc0 == 0xc0 {
			if offset+1 >= len(wire) {
				return 0, fmt.Errorf("short DNS pointer")
			}
			pointer := (length&0x3f)<<8 | int(wire[offset+1])
			if pointer < 12 || pointer >= offset {
				return 0, fmt.Errorf("DNS pointer must refer to an earlier name")
			}
			return offset + 2, nil
		}
		if length&0xc0 != 0 {
			return 0, fmt.Errorf("unsupported DNS label encoding")
		}
		offset++
		if length == 0 {
			return offset, nil
		}
		offset += length
	}
	return 0, fmt.Errorf("DNS name exceeds the target limit")
}

func errorResponse(query dnsmessage.Message, code dnsmessage.RCode) []byte {
	query.Header = dnsmessage.Header{ID: query.ID, Response: true, RecursionDesired: query.RecursionDesired, RecursionAvailable: true, RCode: code}
	wire, _ := query.Pack()
	return wire
}
