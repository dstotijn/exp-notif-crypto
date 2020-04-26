package main

import (
	"bytes"
	"log"
	"time"

	crypto "github.com/dstotijn/exp-notif-crypto"
)

func main() {
	// TemporaryExposureKey should be rolled over after `crypto.EKRollingPeriod` (144)
	// times the interval window (10 minutes). In other words: after 24 hours.
	log.Println("Creating `TemporaryExposureKey` ...")
	tek := crypto.NewTemporaryExposureKey()
	rollingStartNumber := crypto.NewENIntervalNumber(time.Now())
	log.Printf("✅ Generated `TemporaryExposureKey` and `rollingStartNumber`: [% #x], %v",
		tek, rollingStartNumber)

	// `RollingProximityIdentifierKey` is derived from `TemporaryExposureKey`.
	// This RPIK should thus also rolled over every 24 hours.
	log.Println("Creating `RollingProximityIdentifierKey` ...")
	rpik := crypto.NewRollingProximityIdentifierKey(tek)
	log.Printf("✅ Generated `RollingProximityIdentifierKey`: [% #x]", rpik)

	// `AssociatedEncryptedMetadataKey` is derived from `TemporaryExposureKey`.
	// This AEMK should thus also rolled over every 24 hours.
	log.Println("Creating `AssociatedEncryptedMetadataKey` ...")
	aemk := crypto.NewAssociatedEncryptedMetadataKey(tek)
	log.Printf("✅ Generated `AssociatedEncryptedMetadataKey`: [% #x]", aemk)

	// Each time the Bluetooth Low Energy MAC randomized address changes, we
	// should derive a new `Rolling Proximity Identifier`.
	// This privacy-preserving identifier can be broadcast in Bluetooth payloads.
	// For example: an RPI to be broadcast 42 minutes after TEK was created.
	enin := crypto.NewENIntervalNumber(time.Now().Add(42 * time.Minute))
	log.Println("Creating `RollingProximityIdentifier` ...")
	rpi := crypto.NewRollingProximityIdentifier(rpik, enin)
	log.Printf("✅ Generated `RollingProximityIdentifier`: [% #x]", rpi)

	// For every broadcast, `AssociatedEncryptedMetadata` is generated.
	// This data can only be decrypted later if the the user broadcasting it tested
	// positive and revealed (uploaded) their `TemporaryExposure`.
	log.Println("Creating `AssociatedEncryptedMetadata` ...")
	aem := crypto.NewAssociatedEncryptedMetadata(aemk, rpi, []byte("bluetooth metadata..."))
	log.Printf("✅ Generated `AssociatedEncryptedMetadata`: [% #x]\n", aem)

	// In case of positive diagnosis, a set of TEK and rollingStartNumber ("Diagnosis Key") pairs
	// are sent to a central server ...

	// Other users periodically download the Diagnosis Key set and check against
	// repository of received RPIs, by subsequently deriving the RPK and RPI.
	// Let's say for instance another user received the TEK we created above,
	// and they previously received the RPI we broadcast.
	type diagnosisKey struct {
		tek                crypto.TemporaryExposureKey
		rollingStartNumber crypto.ENIntervalNumber
	}
	receivedKeys := []diagnosisKey{
		{tek: tek, rollingStartNumber: rollingStartNumber},                               // Should match
		{tek: tek, rollingStartNumber: rollingStartNumber - crypto.EKRollingPeriod*10*3}, // Should NOT match, TEK from 3 days ago
		{tek: crypto.NewTemporaryExposureKey(), rollingStartNumber: rollingStartNumber},  // Should NOT match, different TEK
	}
	for _, receivedDiagKey := range receivedKeys {
		receivedTEK := receivedDiagKey.tek
		derivedRPIK := crypto.NewRollingProximityIdentifierKey(receivedTEK)
		derivedAEMK := crypto.NewAssociatedEncryptedMetadataKey(receivedTEK)
		var match bool

		for i := 0; i < crypto.EKRollingPeriod; i++ {
			enin := receivedDiagKey.rollingStartNumber + crypto.ENIntervalNumber(i)
			derivedRPI := crypto.NewRollingProximityIdentifier(derivedRPIK, enin)

			if bytes.Equal(derivedRPI[:], rpi[:]) {
				// There's a match!
				// With the derived AEM key, we can now decrypt the AEM that was
				// previously received over Bluetooth.
				metadata := crypto.KeyStream(derivedAEMK[:], derivedRPI[:], aem)
				log.Printf("🎉 MATCH: [% #x], interval since `rollingStartNumber` (%v), metadata: [%s]\n", derivedRPI, i, metadata)

				match = true
				break
			}
		}
		if !match {
			log.Printf("❌ No match: [% #x], rollingStartNumber: %v\n",
				receivedDiagKey.tek, receivedDiagKey.rollingStartNumber)
		}
	}
}
