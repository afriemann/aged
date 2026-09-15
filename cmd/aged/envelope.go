package main

import (
	"bytes"
	"errors"
	"fmt"
)

// envelopePrefix is the fixed literal that opens every aged-v1 envelope.
const envelopePrefix = "aged-v1\nname: "

// errEnvelopeMalformed indicates the plaintext did not match the envelope
// grammar at all (missing prefix, no terminating blank line, etc).
var errEnvelopeMalformed = errors.New("malformed secret envelope")

// errEnvelopeNameMismatch indicates the envelope parsed correctly but its
// bound name does not match the name it was requested under — the anti
// mix-up signal at the heart of the name-binding integrity check.
var errEnvelopeNameMismatch = errors.New("secret envelope name mismatch")

// packEnvelope wraps value in the aged-v1 name-binding envelope:
//
//	aged-v1\nname: <name>\n\n<value>
//
// No escaping of name is performed or required: valid secret names (per
// validName) cannot contain '\n', so the grammar is unambiguous.
func packEnvelope(name string, value []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString(envelopePrefix)
	buf.WriteString(name)
	buf.WriteString("\n\n")
	buf.Write(value)
	return buf.Bytes()
}

// unpackEnvelope parses plaintext as an aged-v1 envelope and verifies its
// bound name equals requestedName. A missing, malformed, or mismatched
// envelope is a hard failure: the value is never returned in that case,
// under any circumstance.
func unpackEnvelope(requestedName string, plaintext []byte) ([]byte, error) {
	if !bytes.HasPrefix(plaintext, []byte(envelopePrefix)) {
		return nil, fmt.Errorf("%w: missing envelope prefix", errEnvelopeMalformed)
	}
	rest := plaintext[len(envelopePrefix):]

	nl := bytes.IndexByte(rest, '\n')
	if nl < 0 {
		return nil, fmt.Errorf("%w: no terminating newline after name", errEnvelopeMalformed)
	}
	boundName := string(rest[:nl])
	afterName := rest[nl+1:]

	if len(afterName) == 0 || afterName[0] != '\n' {
		return nil, fmt.Errorf("%w: missing blank line after name", errEnvelopeMalformed)
	}
	value := afterName[1:]

	if boundName != requestedName {
		return nil, fmt.Errorf("%w: requested %q, envelope bound to %q", errEnvelopeNameMismatch, requestedName, boundName)
	}
	return value, nil
}
