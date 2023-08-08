package sphinx

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

var attributableErrorTestStructure = NewAttrErrorStructure(20, 4, 4)

// TestAttributableOnionFailure checks the ability of sender of payment to
// decode the obfuscated onion error.
func TestAttributableOnionFailure(t *testing.T) {
	t.Parallel()

	t.Run("32 byte hmac", func(t *testing.T) { testAttributableOnionFailure(t, 32) })
	t.Run("4 byte hmac", func(t *testing.T) { testAttributableOnionFailure(t, 4) })
}

// TestAttributableOnionFailure checks the ability of sender of payment to
// decode the obfuscated onion error.
func testAttributableOnionFailure(t *testing.T, hmacBytes int) {
	t.Parallel()

	var structure = NewAttrErrorStructure(27, 8, hmacBytes)

	// Create numHops random sphinx paymentPath.
	sessionKey, paymentPath := generateRandomPath(t)

	// Reduce the error path on one node, in order to check that we are
	// able to receive the error not only from last hop.
	errorPath := paymentPath[:len(paymentPath)-1]

	failureData := bytes.Repeat([]byte{'A'}, minOnionErrorLength)
	sharedSecrets, err := generateSharedSecrets(paymentPath, sessionKey)
	require.NoError(t, err)

	// Emulate creation of the obfuscator on node where error have occurred.
	obfuscator := NewOnionAttrErrorEncrypter(
		sharedSecrets[len(errorPath)-1], structure,
	)

	// Emulate the situation when last hop creates the onion failure
	// message and send it back.
	finalPayload := [8]byte{1}
	obfuscatedData, err := obfuscator.EncryptError(
		true, failureData, finalPayload[:],
	)
	require.NoError(t, err)
	payloads := [][]byte{finalPayload[:]}

	// Emulate that failure message is backward obfuscated on every hop.
	for i := len(errorPath) - 2; i >= 0; i-- {
		// Emulate creation of the obfuscator on forwarding node which
		// propagates the onion failure.
		obfuscator = NewOnionAttrErrorEncrypter(
			sharedSecrets[i], structure,
		)

		intermediatePayload := [8]byte{byte(100 + i)}
		obfuscatedData, err = obfuscator.EncryptError(
			false, obfuscatedData, intermediatePayload[:],
		)
		require.NoError(t, err)

		payloads = append([][]byte{intermediatePayload[:]}, payloads...)
	}

	// Emulate creation of the deobfuscator on the receiving onion error
	// side.
	deobfuscator := NewOnionAttrErrorDecrypter(&Circuit{
		SessionKey:  sessionKey,
		PaymentPath: paymentPath,
	}, structure)

	// Emulate that sender node receive the failure message and trying to
	// unwrap it, by applying obfuscation and checking the hmac.
	decryptedError, err := deobfuscator.DecryptError(obfuscatedData)
	require.NoError(t, err)

	// We should understand the node from which error have been received.
	require.Equal(t,
		errorPath[len(errorPath)-1].SerializeCompressed(),
		decryptedError.Sender.SerializeCompressed())

	require.Equal(t, len(errorPath), decryptedError.SenderIdx)

	// Check that message have been properly de-obfuscated.
	require.Equal(t, failureData, decryptedError.Message)
	require.Equal(t, payloads, decryptedError.Payloads)
}

// TestOnionFailureCorruption checks the ability of sender of payment to
// identify a node on the path that corrupted the failure message.
func TestOnionFailureCorruption(t *testing.T) {
	t.Parallel()

	// Create numHops random sphinx paymentPath.
	sessionKey, paymentPath := generateRandomPath(t)

	// Reduce the error path on one node, in order to check that we are
	// able to receive the error not only from last hop.
	errorPath := paymentPath[:len(paymentPath)-1]

	failureData := bytes.Repeat([]byte{'A'}, minOnionErrorLength)
	sharedSecrets, err := generateSharedSecrets(paymentPath, sessionKey)
	require.NoError(t, err)

	// Emulate creation of the obfuscator on node where error have occurred.
	obfuscator := NewOnionAttrErrorEncrypter(
		sharedSecrets[len(errorPath)-1], attributableErrorTestStructure,
	)

	// Emulate the situation when last hop creates the onion failure
	// message and send it back.
	payload := [4]byte{1}
	obfuscatedData, err := obfuscator.EncryptError(
		true, failureData, payload[:],
	)
	require.NoError(t, err)

	// Emulate that failure message is backward obfuscated on every hop.
	for i := len(errorPath) - 2; i >= 0; i-- {
		// Emulate creation of the obfuscator on forwarding node which
		// propagates the onion failure.
		obfuscator = NewOnionAttrErrorEncrypter(
			sharedSecrets[i], attributableErrorTestStructure,
		)

		payload := [4]byte{byte(100 + i)}
		obfuscatedData, err = obfuscator.EncryptError(
			false, obfuscatedData, payload[:],
		)
		require.NoError(t, err)

		// Hop 1 (the second hop from the sender pov) is corrupting the
		// failure message.
		if i == 1 {
			obfuscatedData[0] ^= 255
		}
	}

	// Emulate creation of the deobfuscator on the receiving onion error
	// side.
	deobfuscator := NewOnionAttrErrorDecrypter(&Circuit{
		SessionKey:  sessionKey,
		PaymentPath: paymentPath,
	}, attributableErrorTestStructure)

	// Emulate that sender node receive the failure message and trying to
	// unwrap it, by applying obfuscation and checking the hmac.
	decryptedError, err := deobfuscator.DecryptError(obfuscatedData)
	require.NoError(t, err)

	// Assert that the second hop is correctly identified as the error
	// source.
	require.Equal(t, 2, decryptedError.SenderIdx)
	require.Nil(t, decryptedError.Message)
}

type specHop struct {
	SharedSecret     string `json:"sharedSecret"`
	EncryptedMessage string `json:"encryptedMessage"`
}

type specVector struct {
	EncodedFailureMessage string `json:"encodedFailureMessage"`

	Hops []specHop `json:"hops"`
}

// TestOnionFailureSpecVector checks that onion error corresponds to the
// specification.
func TestAttributableFailureSpecVector(t *testing.T) {
	t.Parallel()

	vectorBytes, err := os.ReadFile("testdata/attributable_error.json")
	require.NoError(t, err)

	var vector specVector
	require.NoError(t, json.Unmarshal(vectorBytes, &vector))

	failureData, err := hex.DecodeString(vector.EncodedFailureMessage)
	require.NoError(t, err)

	paymentPath, err := getSpecPubKeys()
	require.NoError(t, err)

	sessionKey, err := getSpecSessionKey()
	require.NoError(t, err)

	var obfuscatedData []byte
	sharedSecrets, err := generateSharedSecrets(paymentPath, sessionKey)
	require.NoError(t, err)

	for i, test := range vector.Hops {
		// Decode the shared secret and check that it matchs with
		// specification.
		expectedSharedSecret, err := hex.DecodeString(test.SharedSecret)
		require.NoError(t, err)

		obfuscator := NewOnionAttrErrorEncrypter(
			sharedSecrets[len(sharedSecrets)-1-i],
			attributableErrorTestStructure,
		)

		require.Equal(
			t, expectedSharedSecret, obfuscator.sharedSecret[:],
		)

		payload := [4]byte{0, 0, 0, byte(i + 1)}

		if i == 0 {
			// Emulate the situation when last hop creates the onion
			// failure message and send it back.
			obfuscatedData, err = obfuscator.EncryptError(
				true, failureData, payload[:],
			)
			require.NoError(t, err)
		} else {
			// Emulate the situation when forward node obfuscates
			// the onion failure.
			obfuscatedData, err = obfuscator.EncryptError(
				false, obfuscatedData, payload[:],
			)
			require.NoError(t, err)
		}

		// Decode the obfuscated data and check that it matches the
		// specification.
		expectedEncryptErrorData, err := hex.DecodeString(
			test.EncryptedMessage,
		)
		require.NoError(t, err)
		require.Equal(t, expectedEncryptErrorData, obfuscatedData)
	}

	deobfuscator := NewOnionAttrErrorDecrypter(&Circuit{
		SessionKey:  sessionKey,
		PaymentPath: paymentPath,
	}, attributableErrorTestStructure)

	// Emulate that sender node receives the failure message and trying to
	// unwrap it, by applying obfuscation and checking the hmac.
	decryptedError, err := deobfuscator.DecryptError(obfuscatedData)
	require.NoError(t, err)

	// Check that message have been properly de-obfuscated.
	require.Equal(t, decryptedError.Message, failureData)

	// We should understand the node from which error have been received.
	require.Equal(t,
		decryptedError.Sender.SerializeCompressed(),
		paymentPath[len(paymentPath)-1].SerializeCompressed(),
	)

	require.Equal(t, len(paymentPath), decryptedError.SenderIdx)
}

// TestAttributableOnionFailureZeroesMessage checks that a garbage failure is
// attributed to the first hop.
func TestAttributableOnionFailureZeroesMessage(t *testing.T) {
	t.Parallel()

	// Create numHops random sphinx paymentPath.
	sessionKey, paymentPath := generateRandomPath(t)

	// Emulate creation of the deobfuscator on the receiving onion error
	// side.
	deobfuscator := NewOnionAttrErrorDecrypter(&Circuit{
		SessionKey:  sessionKey,
		PaymentPath: paymentPath,
	}, attributableErrorTestStructure)

	// Emulate that sender node receive the failure message and trying to
	// unwrap it, by applying obfuscation and checking the hmac.
	obfuscatedData := make([]byte, 20000)

	decryptedError, err := deobfuscator.DecryptError(obfuscatedData)
	require.NoError(t, err)

	require.Equal(t, 1, decryptedError.SenderIdx)
}

// TestAttributableOnionFailureShortMessage checks that too short failure is
// attributed to the first hop.
func TestAttributableOnionFailureShortMessage(t *testing.T) {
	t.Parallel()

	// Create numHops random sphinx paymentPath.
	sessionKey, paymentPath := generateRandomPath(t)

	// Emulate creation of the deobfuscator on the receiving onion error
	// side.
	deobfuscator := NewOnionAttrErrorDecrypter(&Circuit{
		SessionKey:  sessionKey,
		PaymentPath: paymentPath,
	}, attributableErrorTestStructure)

	// Emulate that sender node receive the failure message and trying to
	// unwrap it, by applying obfuscation and checking the hmac.
	obfuscatedData := make([]byte, deobfuscator.hmacsAndPayloadsLen()-1)

	decryptedError, err := deobfuscator.DecryptError(obfuscatedData)
	require.NoError(t, err)

	require.Equal(t, 1, decryptedError.SenderIdx)
}

func generateRandomPath(t *testing.T) (*btcec.PrivateKey, []*btcec.PublicKey) {
	paymentPath := make([]*btcec.PublicKey, 5)
	for i := 0; i < len(paymentPath); i++ {
		privKey, err := btcec.NewPrivateKey()
		require.NoError(t, err)

		paymentPath[i] = privKey.PubKey()
	}

	sessionKey, _ := btcec.PrivKeyFromBytes(bytes.Repeat([]byte{'A'}, 32))

	return sessionKey, paymentPath
}

func generateHashList(values ...int) []byte {
	var b bytes.Buffer
	for _, v := range values {
		hash := [32]byte{byte(v)}
		b.Write(hash[:])
	}

	return b.Bytes()
}

const testMaxHops = 4

// Generate a list of 4+3+2+1 = 10 unique hmacs. The length of this list is
// fixed for the chosen maxHops.
func createTestHmacs() []byte {
	return generateHashList(
		43, 42, 41, 40,
		32, 31, 30,
		21, 20,
		10,
	)
}

const testHmacBytes = 32

func TestWriteDownstreamHmacs(t *testing.T) {
	require := require.New(t)

	hmacs := createTestHmacs()

	test := func(position int, expectedValues []int) {
		var b bytes.Buffer
		writeDownstreamHmacs(
			position, testMaxHops, hmacs, testHmacBytes, &b,
		)

		expectedHashes := generateHashList(expectedValues...)
		require.Equal(expectedHashes, b.Bytes())
	}

	// Assuming the current node is in the position furthest away from the
	// error source, we expect three downstream hmacs to be relevant.
	test(3, []int{32, 21, 10})

	// Assuming the current node is in positions closer to the error source,
	// fewer hmacs become relevant.
	test(2, []int{31, 20})
	test(1, []int{30})
	test(0, []int{})
}

func TestShiftHmacsRight(t *testing.T) {
	require := require.New(t)

	hmacs := createTestHmacs()

	o := NewOnionAttrErrorEncrypter(
		Hash256{},
		NewAttrErrorStructure(testMaxHops, 0, 32),
	)
	o.shiftHmacsRight(hmacs)

	expectedHmacs := generateHashList(
		// Previous values are zeroed out.
		0, 0, 0, 0,

		// Previous first node hmacs minus the hmac representing the
		// position farthest away from the error source.
		42, 41, 40,

		// And so on for the other nodes.
		31, 30,
		20,
	)

	require.Equal(expectedHmacs, hmacs)
}

func TestShiftHmacsLeft(t *testing.T) {
	require := require.New(t)

	hmacs := createTestHmacs()

	o := NewOnionAttrErrorDecrypter(
		nil,
		NewAttrErrorStructure(testMaxHops, 0, 32),
	)
	o.shiftHmacsLeft(hmacs)

	expectedHmacs := generateHashList(
		// The hmacs of the second hop now become the first hop hmacs.
		// The slot corresponding to the position farthest away from the
		// error source remains empty. Because we are shifting, this can
		// never be the position of the first hop.
		0, 32, 31, 30,

		// Continue this same scheme for the downstream hops.
		0, 21, 20,
		0, 10,
		0,
	)

	require.Equal(expectedHmacs, hmacs)
}
