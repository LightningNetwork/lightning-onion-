package sphinx

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"
)

type payloadSource byte

const (
	// payloadIntermediateNode is a marker to signal that this attributable
	// error payload is originating from a node between the payer and the
	// error source.
	payloadIntermediateNode payloadSource = 0

	// payloadErrorNode is a marker to signal that this attributable error
	// payload is originating from the error source.
	payloadErrorNode payloadSource = 1
)

// AttrErrorStructure contains the parameters that define the structure
// of the error message that is passed back.
type AttrErrorStructure struct {
	// hopCount is the assumed maximum number of hops in the path.
	hopCount int

	// fixedPayloadLen is the length of the payload data that each hop along
	// the route can add.
	fixedPayloadLen int

	// hmacSize is the number of bytes that is reserved for each hmac.
	hmacSize int

	zeroHmac []byte
}

func NewAttrErrorStructure(hopCount int, fixedPayloadLen int,
	hmacSize int) *AttrErrorStructure {

	return &AttrErrorStructure{
		hopCount:        hopCount,
		fixedPayloadLen: fixedPayloadLen,
		hmacSize:        hmacSize,

		zeroHmac: make([]byte, hmacSize),
	}
}

// HopCount returns the assumed maximum number of hops in the path.
func (o *AttrErrorStructure) HopCount() int {
	return o.hopCount
}

// FixedPayloadLen returns the length of the payload data that each hop along
// the route can add.
func (o *AttrErrorStructure) FixedPayloadLen() int {
	return o.fixedPayloadLen
}

// HmacSize returns the number of bytes that is reserved for each hmac.
func (o *AttrErrorStructure) HmacSize() int {
	return o.hmacSize
}

// totalHmacs is the total number of hmacs that is present in the failure
// message. Every hop adds HopCount hmacs to the message, but as the error
// back-propagates, downstream hmacs can be pruned. This results in the number
// of hmacs for each hop decreasing by one for each step that we move away from
// the current node.
func (o *AttrErrorStructure) totalHmacs() int {
	return (o.hopCount * (o.hopCount + 1)) / 2
}

// allHmacsLen is the total length in the bytes of all hmacs in the failure
// message.
func (o *AttrErrorStructure) allHmacsLen() int {
	return o.totalHmacs() * o.hmacSize
}

// hmacsAndPayloadsLen is the total length in bytes of all hmacs and payloads
// together.
func (o *AttrErrorStructure) hmacsAndPayloadsLen() int {
	return o.allHmacsLen() + o.allPayloadsLen()
}

// allPayloadsLen is the total length in bytes of all payloads in the failure
// message.
func (o *AttrErrorStructure) allPayloadsLen() int {
	return o.payloadLen() * o.hopCount
}

// payloadLen is the size of the per-node payload. It consists of a 1-byte
// payload type followed by the payload data.
func (o *AttrErrorStructure) payloadLen() int {
	return 1 + o.fixedPayloadLen
}

// message returns a slice containing the message in the given failure data
// block. The message is positioned at the beginning of the block.
func (o *AttrErrorStructure) message(data []byte) []byte {
	return data[:len(data)-o.hmacsAndPayloadsLen()]
}

// payloads returns a slice containing all payloads in the given failure
// data block. The payloads follow the message in the block.
func (o *AttrErrorStructure) payloads(data []byte) []byte {
	dataLen := len(data)

	return data[dataLen-o.hmacsAndPayloadsLen() : dataLen-o.allHmacsLen()]
}

// hmacs returns a slice containing all hmacs in the given failure data block.
// The hmacs are positioned at the end of the data block.
func (o *AttrErrorStructure) hmacs(data []byte) []byte {
	return data[len(data)-o.allHmacsLen():]
}

// calculateHmac calculates an hmac given a shared secret and a presumed
// position in the path. Position is expressed as the distance to the error
// source. The error source itself is at position 0.
func (o *AttrErrorStructure) calculateHmac(sharedSecret Hash256,
	position int, message, payloads, hmacs []byte) []byte {

	umKey := generateKey("um", &sharedSecret)
	hash := hmac.New(sha256.New, umKey[:])

	// Include message.
	_, _ = hash.Write(message)

	// Include payloads including our own.
	_, _ = hash.Write(payloads[:(position+1)*o.payloadLen()])

	// Include downstream hmacs.
	writeDownstreamHmacs(position, o.hopCount, hmacs, o.hmacSize, hash)

	hmac := hash.Sum(nil)

	return hmac[:o.hmacSize]
}

// writeDownstreamHmacs writes the hmacs of downstream nodes that are relevant
// for the given position to a writer instance. Position is expressed as the
// distance to the error source. The error source itself is at position 0.
func writeDownstreamHmacs(position, maxHops int, hmacs []byte, hmacBytes int,
	w io.Writer) {

	// Track the index of the next hmac to write in a variable. The first
	// maxHops slots are reserved for the hmacs of the current hop and can
	// therefore be skipped. The first hmac to write is part of the block of
	// hmacs that was written by the first downstream node. Which hmac
	// exactly is determined by the assumed position of the current node.
	var hmacIdx = maxHops + (maxHops - position - 1)

	// Iterate over all downstream nodes.
	for j := 0; j < position; j++ {
		_, _ = w.Write(
			hmacs[hmacIdx*hmacBytes : (hmacIdx+1)*hmacBytes],
		)

		// Calculate the total number of hmacs in the block of the
		// current downstream node.
		blockSize := maxHops - j - 1

		// Skip to the next block. The new hmac index will point to the
		// hmac that corresponds to the next downstream node which is
		// one step closer to the assumed error source.
		hmacIdx += blockSize
	}
}
