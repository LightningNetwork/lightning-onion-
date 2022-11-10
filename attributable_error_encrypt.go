package sphinx

import (
	"errors"
	"fmt"
)

// ErrInvalidStructure is returned when the failure message has an invalid
// structure. This is typically returned for messages that are shorter than the
// minimum length.
var ErrInvalidStructure = errors.New("failure message has invalid structure")

// NewOnionAttrErrorEncrypter creates new instance of the onion
// encrypter backed by the passed shared secret.
func NewOnionAttrErrorEncrypter(sharedSecret Hash256,
	structure *AttrErrorStructure) *OnionAttrErrorEncrypter {

	return &OnionAttrErrorEncrypter{
		AttrErrorStructure: *structure,

		sharedSecret: sharedSecret,
	}
}

// OnionAttrErrorEncrypter is a struct that's used to implement
// attributable onion error encryption as defined within BOLT0004.
type OnionAttrErrorEncrypter struct {
	AttrErrorStructure

	sharedSecret Hash256
}

func (o *OnionAttrErrorEncrypter) shiftHmacsRight(hmacs []byte) {
	totalHmacs := (o.hopCount * (o.hopCount + 1)) / 2

	// Work from right to left to avoid overwriting data that is still
	// needed.
	srcIdx := totalHmacs - 2
	destIdx := totalHmacs - 1

	// The variable copyLen contains the number of hmacs to copy for the
	// current hop.
	copyLen := 1
	for i := 0; i < o.hopCount-1; i++ {
		// Shift the hmacs to the right for the current hop. The hmac
		// corresponding to the assumed position that is farthest away
		// from the error source is discarded.
		copy(
			hmacs[destIdx*o.hmacSize:],
			hmacs[srcIdx*o.hmacSize:(srcIdx+copyLen)*o.hmacSize],
		)

		// The number of hmacs to copy increases by one for each
		// iteration. The further away from the error source, the more
		// downstream hmacs exist that are relevant.
		copyLen++

		// Update indices backwards for the next iteration.
		srcIdx -= copyLen + 1
		destIdx -= copyLen
	}

	// Zero out the hmac slots corresponding to every possible position
	// relative to the error source for the current hop. This is not
	// strictly necessary as these slots are overwritten anyway, but we
	// clear them for cleanliness.
	for i := 0; i < o.hopCount; i++ {
		copy(hmacs[i*o.hmacSize:], o.zeroHmac)
	}
}

func (o *OnionAttrErrorEncrypter) shiftPayloadsRight(payloads []byte) {
	copy(payloads[o.payloadLen():], payloads)
}

// addHmacs updates the failure data with a series of hmacs corresponding to all
// possible positions in the path for the current node.
func (o *OnionAttrErrorEncrypter) addHmacs(data []byte) {
	message := o.message(data)
	payloads := o.payloads(data)
	hmacs := o.hmacs(data)

	for i := 0; i < o.hopCount; i++ {
		position := o.hopCount - i - 1
		hmac := o.calculateHmac(
			o.sharedSecret, position, message, payloads, hmacs,
		)

		copy(hmacs[i*o.hmacSize:], hmac)
	}
}

// EncryptError is used to make data obfuscation using the generated shared
// secret.
//
// In context of Lightning Network is either used by the nodes in order to make
// initial obfuscation with the creation of the hmac or by the forwarding nodes
// for backward failure obfuscation of the onion failure blob. By obfuscating
// the onion failure on every node in the path we are adding additional step of
// the security and barrier for malware nodes to retrieve valuable information.
// The reason for using onion obfuscation is to not give away to the nodes in
// the payment path the information about the exact failure and its origin.
func (o *OnionAttrErrorEncrypter) EncryptError(initial bool,
	data []byte, payload []byte) ([]byte, error) {

	if len(payload) > o.fixedPayloadLen {
		return nil, fmt.Errorf("payload exceeds maximum length")
	}

	if initial {
		if len(data) < minPaddedOnionErrorLength {
			return nil, fmt.Errorf(
				"initial data size less than %v",
				minPaddedOnionErrorLength,
			)
		}

		data = o.initializePayload(data, payload)
	} else {
		if len(data) <
			minPaddedOnionErrorLength+o.hmacsAndPayloadsLen() {

			return nil, ErrInvalidStructure
		}

		o.addIntermediatePayload(data, payload)

		// Shift hmacs to create space for the new hmacs.
		o.shiftHmacsRight(o.hmacs(data))
	}

	// Update hmac block.
	o.addHmacs(data)

	// Obfuscate.
	return onionEncrypt(&o.sharedSecret, data), nil
}

func (o *OnionAttrErrorEncrypter) initializePayload(message []byte,
	payload []byte) []byte {

	// Add space for payloads and hmacs.
	data := make([]byte, len(message)+o.hmacsAndPayloadsLen())
	copy(data, message)

	payloads := o.payloads(data)

	// Signal final hops in the payload.
	addPayload(payloads, payloadErrorNode, payload)

	return data
}

func (o *OnionAttrErrorEncrypter) addIntermediatePayload(data []byte,
	payload []byte) {

	payloads := o.payloads(data)

	// Shift payloads to create space for the new payload.
	o.shiftPayloadsRight(payloads)

	// Signal intermediate hop in the payload.
	addPayload(payloads, payloadIntermediateNode, payload)
}

func addPayload(payloads []byte, source payloadSource,
	payload []byte) {

	payloads[0] = byte(source)
	copy(payloads[1:], payload)
}
