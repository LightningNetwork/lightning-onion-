package sphinx

import (
	"bytes"
	"errors"
	"fmt"
)

// DecryptedAttrError contains the decrypted attributable error message
// and its sender.
type DecryptedAttrError struct {
	DecryptedError

	// Payloads is an array of data blocks reported by each node on the
	// (error) path.
	Payloads [][]byte
}

// OnionAttrErrorDecrypter is a struct that's used to decrypt
// attributable onion errors in response to failed HTLC routing attempts
// according to BOLT#4.
type OnionAttrErrorDecrypter struct {
	AttrErrorStructure

	circuit *Circuit
}

// NewOnionAttrErrorDecrypter creates new instance of an attributable
// error onion decrypter.
func NewOnionAttrErrorDecrypter(circuit *Circuit,
	structure *AttrErrorStructure) *OnionAttrErrorDecrypter {

	return &OnionAttrErrorDecrypter{
		AttrErrorStructure: *structure,
		circuit:            circuit,
	}
}

// DecryptError attempts to decrypt the passed encrypted error response. The
// onion failure is encrypted in backward manner, starting from the node where
// error have occurred. As a result, in order to decrypt the error we need get
// all shared secret and apply decryption in the reverse order. A structure is
// returned that contains the decrypted error message and information on the
// sender.
func (o *OnionAttrErrorDecrypter) DecryptError(encryptedData []byte) (
	*DecryptedAttrError, error) {

	// Ensure the error message length is enough to contain the payloads and
	// hmacs blocks. Otherwise blame the first hop.
	if len(encryptedData) <
		minPaddedOnionErrorLength+o.hmacsAndPayloadsLen() {

		return &DecryptedAttrError{
			DecryptedError: DecryptedError{
				SenderIdx: 1,
				Sender:    o.circuit.PaymentPath[0],
			},
		}, nil
	}

	sharedSecrets, err := generateSharedSecrets(
		o.circuit.PaymentPath,
		o.circuit.SessionKey,
	)
	if err != nil {
		return nil, fmt.Errorf("error generating shared secret: "+
			"%w", err)
	}

	var (
		sender      int
		msg         []byte
		dummySecret Hash256
	)
	copy(dummySecret[:], bytes.Repeat([]byte{1}, 32))

	// We'll iterate a constant amount of hops to ensure that we don't give
	// away an timing information pertaining to the position in the route
	// that the error emanated from.
	hopPayloads := make([][]byte, 0)
	for i := 0; i < o.hopCount; i++ {
		var sharedSecret Hash256

		// If we've already found the sender, then we'll use our dummy
		// secret to continue decryption attempts to fill out the rest
		// of the loop. Otherwise, we'll use the next shared secret in
		// line.
		if sender != 0 || i > len(sharedSecrets)-1 {
			sharedSecret = dummySecret
		} else {
			sharedSecret = sharedSecrets[i]
		}

		// With the shared secret, we'll now strip off a layer of
		// encryption from the encrypted error payload.
		encryptedData = onionEncrypt(&sharedSecret, encryptedData)

		message := o.message(encryptedData)
		payloads := o.payloads(encryptedData)
		hmacs := o.hmacs(encryptedData)

		position := o.hopCount - i - 1
		expectedHmac := o.calculateHmac(
			sharedSecret, position, message, payloads, hmacs,
		)
		actualHmac := hmacs[i*o.hmacSize : (i+1)*o.hmacSize]

		// If the hmac does not match up, exit with a nil message but
		// only after finishing the constant number of iterations.
		if !bytes.Equal(actualHmac, expectedHmac) && sender == 0 {
			sender = i + 1
			msg = nil
		}

		// Extract the payload and exit with a nil message if it is
		// invalid.
		source, payload, err := o.extractPayload(payloads)
		if sender == 0 {
			if err != nil {
				sender = i + 1
				msg = nil
			}

			// Store data reported by this node.
			hopPayloads = append(hopPayloads, payload)

			// If we are at the node that is the source of the
			// error, we can now save the message in our return
			// variable.
			if source == payloadErrorNode {
				sender = i + 1
				msg = message
			}
		}

		// Shift payloads and hmacs to the left to prepare for the next
		// iteration.
		o.shiftPayloadsLeft(payloads)
		o.shiftHmacsLeft(hmacs)
	}

	// If the sender index is still zero, all hmacs checked out but none of
	// the payloads was a final payload. In this case we must be dealing
	// with a max length route and a final hop that returned an intermediate
	// payload. Blame the final hop.
	if sender == 0 {
		sender = o.hopCount
		msg = nil
	}

	return &DecryptedAttrError{
		DecryptedError: DecryptedError{
			SenderIdx: sender,
			Sender:    o.circuit.PaymentPath[sender-1],
			Message:   msg,
		},
		Payloads: hopPayloads,
	}, nil
}

func (o *OnionAttrErrorDecrypter) shiftHmacsLeft(hmacs []byte) {
	// Work from left to right to avoid overwriting data that is still
	// needed later on in the shift operation.
	srcIdx := o.hopCount
	destIdx := 0
	copyLen := o.hopCount - 1
	for i := 0; i < o.hopCount-1; i++ {
		// Clear first hmac slot. This slot is for the position farthest
		// away from the error source. Because we are shifting, this
		// cannot be relevant.
		copy(hmacs[destIdx*o.hmacSize:], o.zeroHmac)

		// The hmacs of the downstream hop become the remaining hmacs
		// for the current hop.
		copy(
			hmacs[(destIdx+1)*o.hmacSize:],
			hmacs[srcIdx*o.hmacSize:(srcIdx+copyLen)*o.hmacSize],
		)

		srcIdx += copyLen
		destIdx += copyLen + 1
		copyLen--
	}

	// Clear the very last hmac slot. Because we just shifted, the most
	// downstream hop can never be the error source.
	copy(hmacs[destIdx*o.hmacSize:], o.zeroHmac)
}

func (o *OnionAttrErrorDecrypter) shiftPayloadsLeft(payloads []byte) {
	copy(payloads, payloads[o.payloadLen():o.hopCount*o.payloadLen()])
}

// extractPayload extracts the payload and payload origin information from the
// given byte slice.
func (o *OnionAttrErrorDecrypter) extractPayload(payloadBytes []byte) (
	payloadSource, []byte, error) {

	source := payloadSource(payloadBytes[0])

	// Validate source indicator.
	if source != payloadErrorNode && source != payloadIntermediateNode {
		return 0, nil, errors.New("invalid payload source indicator")
	}

	// Extract payload.
	payload := make([]byte, o.fixedPayloadLen)
	copy(payload, payloadBytes[1:o.payloadLen()])

	return source, payload, nil
}
