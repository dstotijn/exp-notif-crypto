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

type ENIntervalNumber uint32

type TemporaryExposureKey [16]byte

type RollingProximityIdentifierKey [16]byte

type RollingProximityIdentifier [16]byte

type AssociatedEncryptedMetadataKey [16]byte

type AssociatedEncryptedMetadata [16]byte

const EKRollingPeriod = 144

var hash = sha256.New

func NewTemporaryExposureKey() (tek TemporaryExposureKey) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	copy(tek[:], buf)

	return
}

func NewENIntervalNumber(t time.Time) ENIntervalNumber {
	// The rollover interval (e.g. time window) is 10 minutes.
	return ENIntervalNumber(t.Unix() / (60 * 10))
}

func NewRollingProximityIdentifierKey(tek TemporaryExposureKey) RollingProximityIdentifierKey {
	return derivedKey(tek, []byte("EN-RPIK"))
}

func NewRollingProximityIdentifier(rpik RollingProximityIdentifierKey, enin ENIntervalNumber) (rpi RollingProximityIdentifier) {
	block, err := aes.NewCipher(rpik[:])
	if err != nil {
		panic(err)
	}

	paddedData := make([]byte, 16)
	copy(paddedData[:6], []byte("EN-RPI"))
	binary.LittleEndian.PutUint32(paddedData[12:], uint32(enin))

	buf := make([]byte, 16)
	block.Encrypt(buf, paddedData)
	copy(rpi[:], buf)

	return
}

func NewAssociatedEncryptedMetadataKey(tek TemporaryExposureKey) AssociatedEncryptedMetadataKey {
	return derivedKey(tek, []byte("CT-AEMK"))
}

func NewAssociatedEncryptedMetadata(
	aemk AssociatedEncryptedMetadataKey,
	rpi RollingProximityIdentifier,
	metadata []byte,
) []byte {
	return KeyStream(aemk[:], rpi[:], metadata)
}

func KeyStream(key []byte, iv []byte, src []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	dst := make([]byte, len(src))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(dst, src)

	return dst
}

func derivedKey(in [16]byte, info []byte) (out [16]byte) {
	hkdf := hkdf.New(hash, in[:], nil, info)
	buf := make([]byte, 16)
	if _, err := io.ReadFull(hkdf, buf); err != nil {
		panic(err)
	}
	copy(out[:], buf)
	return
}
