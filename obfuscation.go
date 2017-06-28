package sphinx

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/roasbeef/btcd/btcec"
)

// onionObfuscation obfuscates the data with compliance with BOLT#4.
//
// In context of Lightning Network this function is used by sender to obfuscate
// the onion failure and by receiver to unwrap the failure data.
func onionObfuscation(sharedSecret [sha256.Size]byte,
	data []byte) []byte {
	obfuscatedData := make([]byte, len(data))
	ammagKey := generateKey("ammag", sharedSecret)
	streamBytes := generateCipherStream(ammagKey, uint(len(data)))
	xor(obfuscatedData, data, streamBytes)
	return obfuscatedData
}

// OnionObfuscator represent serializable object which is able to convert the
// data to the obfuscated blob, by applying the stream of data generated by
// the shared secret.
//
// In context of Lightning Network the obfuscated data is usually a failure
// which will be propagated back to payment sender, and obfuscated by the
// forwarding nodes.
type OnionObfuscator struct {
	sharedSecret [sha256.Size]byte
}

// NewOnionObfuscator creates new instance of onion obfuscator.
func NewOnionObfuscator(router *Router, ephemeralKey *btcec.PublicKey) (*OnionObfuscator,
	error) {

	sharedSecret, err := router.generateSharedSecret(ephemeralKey)
	if err != nil {
		return nil, err
	}

	return &OnionObfuscator{
		sharedSecret: sharedSecret,
	}, nil
}

// Obfuscate is used to make data obfuscation using the generated shared secret.
//
// In context of Lightning Network is either used by the nodes in order to
// make initial obfuscation with the creation of the hmac or by the forwarding
// nodes for backward failure obfuscation of the onion failure blob. By
// obfuscating the onion failure on every node in the path we are adding
// additional step of the security and barrier for malware nodes to retrieve
// valuable information. The reason for using onion obfuscation is to not give
// away to the nodes in the payment path the information about the exact failure
// and its origin.
func (o *OnionObfuscator) Obfuscate(initial bool, data []byte) []byte {
	if initial {
		umKey := generateKey("um", o.sharedSecret)
		hash := hmac.New(sha256.New, umKey[:])
		hash.Write(data)
		h := hash.Sum(nil)
		data = append(h, data...)
	}

	return onionObfuscation(o.sharedSecret, data)
}

// Decode initializes the obfuscator from the byte stream.
func (o *OnionObfuscator) Decode(r io.Reader) error {
	_, err := r.Read(o.sharedSecret[:])
	return err
}

// Encode writes converted obfuscator in the byte stream.
func (o *OnionObfuscator) Encode(w io.Writer) error {
	_, err := w.Write(o.sharedSecret[:])
	return err
}

// Circuit is used encapsulate the data which is needed for data deobfuscation.
type Circuit struct {
	// SessionKey is the key which have been used during generation of the
	// shared secrets.
	SessionKey *btcec.PrivateKey

	// PaymentPath is the pub keys of the nodes in the payment path.
	PaymentPath []*btcec.PublicKey
}

// Decode initializes the circuit from the byte stream.
func (c *Circuit) Decode(r io.Reader) error {
	var keyLength [1]byte
	if _, err := r.Read(keyLength[:]); err != nil {
		return err
	}

	sessionKeyData := make([]byte, uint8(keyLength[0]))
	if _, err := r.Read(sessionKeyData[:]); err != nil {
		return err
	}

	c.SessionKey, _ = btcec.PrivKeyFromBytes(btcec.S256(), sessionKeyData)
	var pathLength [1]byte
	if _, err := r.Read(pathLength[:]); err != nil {
		return err
	}
	c.PaymentPath = make([]*btcec.PublicKey, uint8(pathLength[0]))

	for i := 0; i < len(c.PaymentPath); i++ {
		var pubKeyData [btcec.PubKeyBytesLenCompressed]byte
		if _, err := r.Read(pubKeyData[:]); err != nil {
			return err
		}

		pubKey, err := btcec.ParsePubKey(pubKeyData[:], btcec.S256())
		if err != nil {
			return err
		}
		c.PaymentPath[i] = pubKey
	}

	return nil
}

// Encode writes converted circuit in the byte stream.
func (c *Circuit) Encode(w io.Writer) error {
	var keyLength [1]byte
	keyLength[0] = uint8(len(c.SessionKey.Serialize()))
	if _, err := w.Write(keyLength[:]); err != nil {
		return err
	}

	if _, err := w.Write(c.SessionKey.Serialize()); err != nil {
		return err
	}

	var pathLength [1]byte
	pathLength[0] = uint8(len(c.PaymentPath))
	if _, err := w.Write(pathLength[:]); err != nil {
		return err
	}

	for _, pubKey := range c.PaymentPath {
		if _, err := w.Write(pubKey.SerializeCompressed()); err != nil {
			return err
		}
	}

	return nil
}

// OnionDeobfuscator represents the serializable object which encapsulate the
// all necessary data to properly de-obfuscate previously obfuscated data.
// In context of Lightning Network the data which have to be deobfuscated
// usually is onion failure.
type OnionDeobfuscator struct {
	circuit *Circuit
}

// NewOnionDeobfuscator creates new instance of onion deobfuscator.
func NewOnionDeobfuscator(circuit *Circuit) *OnionDeobfuscator {
	return &OnionDeobfuscator{
		circuit: circuit,
	}
}

// Deobfuscate makes data deobfuscation. The onion failure is obfuscated in
// backward manner, starting from the node where error have occurred, so in
// order to deobfuscate the error we need get all shared secret and apply
// obfuscation in reverse order.
func (o *OnionDeobfuscator) Deobfuscate(obfuscatedData []byte) (*btcec.PublicKey,
	[]byte, error) {
	for i, sharedSecret := range generateSharedSecrets(o.circuit.PaymentPath,
		o.circuit.SessionKey) {
		obfuscatedData = onionObfuscation(sharedSecret, obfuscatedData)
		umKey := generateKey("um", sharedSecret)

		// Split the data and hmac.
		expectedMac := obfuscatedData[:sha256.Size]
		data := obfuscatedData[sha256.Size:]

		// Calculate the real hmac.
		h := hmac.New(sha256.New, umKey[:])
		h.Write(data)
		realMac := h.Sum(nil)

		if hmac.Equal(realMac, expectedMac) {
			return o.circuit.PaymentPath[i], data, nil
		}
	}

	return nil, nil, errors.New("unable to retrieve onion failure")
}

// Decode writes converted deobfucator in the byte stream.
func (o *OnionDeobfuscator) Decode(r io.Reader) error {
	return o.circuit.Decode(r)
}

// Encode writes converted deobfucator in the byte stream.
func (o *OnionDeobfuscator) Encode(w io.Writer) error {
	return o.circuit.Encode(w)
}
