package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"time"

	"golang.org/x/crypto/hkdf"
)

// TemporaryExposureKey is a key generated using a cryptographic random
// number generator. All devices generate a new TEK at the same time — at the
// beginning of an interval whose ENIntervalNumber is a multiple of
// EKRollingPeriod.
type TemporaryExposureKey [16]byte

// ENIntervalNumber is a number for each 10 minute time window that’s shared
// between all devices participating in the protocol. These time windows are
// derived from timestamps in Unix Epoch Time.
type ENIntervalNumber uint32

// RollingProximityIdentifierKey (RPIK) is derived from a TemporaryExposureKey
// and is used in order to derive RollingProximityIdentifier values.
type RollingProximityIdentifierKey [16]byte

// RollingProximityIdentifier is a privacy-preserving identifier that is broadcast
// in Bluetooth payloads.
type RollingProximityIdentifier [16]byte

// AssociatedEncryptedMetadataKey is derived from a TemporaryExposureKey in
// order to encrypt additional metadata.
type AssociatedEncryptedMetadataKey [16]byte

// AssociatedEncryptedMetadata is data encrypted along with the RollingProximityIdentifier,
// and can only be decrypted later if the user broadcasting it tested positive
// and reveals their TemporaryExposure Key.
type AssociatedEncryptedMetadata [16]byte

// EKRollingPeriod is the duration for which a TemporaryExposureKey is valid
// (in multiples of 10 minutes). In the protocol, EKRollingPeriod is defined as
// 144, achieving a key validity of 24 hours.
const EKRollingPeriod = 144

// NewTemporaryExposureKey returns a new TemporaryExposureKey using `crypto/rand`.
func NewTemporaryExposureKey() (tek TemporaryExposureKey) {
	if _, err := rand.Read(tek[:]); err != nil {
		panic(err)
	}
	return
}

// NewENIntervalNumber returns the `ENIntervalNumber`, e.g. the 10 minute time
// window since Unix Epoch Time, that the given time `t` is in.
func NewENIntervalNumber(t time.Time) ENIntervalNumber {
	return ENIntervalNumber(t.Unix() / (60 * 10))
}

// NewRollingStartNumber returns the `ENIntervalNumber` for the start period of
// a TemporaryExposureKey with generation time `t`.
func NewRollingStartNumber(t time.Time) ENIntervalNumber {
	return NewENIntervalNumber(t) / EKRollingPeriod * EKRollingPeriod
}

// NewRollingProximityIdentifierKey returns a new RollingProximityIdentifierKey.
// It uses HKDF to derive a key from the given TemporaryExposureKey.
func NewRollingProximityIdentifierKey(tek TemporaryExposureKey) RollingProximityIdentifierKey {
	return derivedKey(tek, []byte("EN-RPIK"))
}

// NewRollingProximityIdentifier returns a new RollingProximityIdentifier.
func NewRollingProximityIdentifier(rpik RollingProximityIdentifierKey, enin ENIntervalNumber) (rpi RollingProximityIdentifier) {
	block, err := aes.NewCipher(rpik[:])
	if err != nil {
		panic(err)
	}

	var paddedData [16]byte
	copy(paddedData[:6], []byte("EN-RPI"))
	binary.LittleEndian.PutUint32(paddedData[12:], uint32(enin))

	block.Encrypt(rpi[:], paddedData[:])

	return
}

// NewAssociatedEncryptedMetadataKey returns a new AssociatedEncryptedMetadataKey.
// It uses HKDF to derive a key from the given TemporaryExposureKey.
func NewAssociatedEncryptedMetadataKey(tek TemporaryExposureKey) AssociatedEncryptedMetadataKey {
	return derivedKey(tek, []byte("CT-AEMK"))
}

// XORKeyStreamAssociatedMetadata is used to encrypt or decrypt metadata.
func XORKeyStreamAssociatedMetadata(
	aemk AssociatedEncryptedMetadataKey,
	rpi RollingProximityIdentifier,
	data []byte,
) []byte {
	return keyStream(aemk, rpi[:], data)
}

func keyStream(key [16]byte, iv []byte, src []byte) []byte {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}

	dst := make([]byte, len(src))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(dst, src)

	return dst
}

func derivedKey(in [16]byte, info []byte) (out [16]byte) {
	hkdf := hkdf.New(sha256.New, in[:], nil, info)
	if _, err := io.ReadFull(hkdf, out[:]); err != nil {
		panic(err)
	}
	return
}
