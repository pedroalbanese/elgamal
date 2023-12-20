package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"math/big"
)

func getGAndP(size string) (g, p *big.Int, err error) {
	switch size {
	case "512":
		p, _ = new(big.Int).SetString("FCA682CE8E12CABA26EFCCF7110E526DB078B05EDECBCD1EB4A208F3AE1617AE01F35B91A47E6DF63413C5E12ED0899BCD132ACD50D99151BDC43EE737592E17", 16)
		g, _ = new(big.Int).SetString("678471B27A9CF44EE91A49C5147DB1A9AAF244F05A434D6486931D2D14271B9E35030B71FD73DA179069B32E2935630E1C2062354D0DA20A6C416E50BE794CA4", 16)
	case "768":
		p, _ = new(big.Int).SetString("E9E642599D355F37C97FFD3567120B8E25C9CD43E927B3A9670FBEC5D890141922D2C3B3AD2480093799869D1E846AAB49FAB0AD26D2CE6A22219D470BCE7D777D4A21FBE9C270B57F607002F3CEF8393694CF45EE3688C11A8C56AB127A3DAF", 16)
		g, _ = new(big.Int).SetString("30470AD5A005FB14CE2D9DCD87E38BC7D1B1C5FACBAECBE95F190AA7A31D23C4DBBCBE06174544401A5B2C020965D8C2BD2171D3668445771F74BA084D2029D83C1C158547F3A9F1A2715BE23D51AE4D3E5A1F6A7064F316933A346D3F529252", 16)
	case "1024":
		p, _ = new(big.Int).SetString("FD7F53811D75122952DF4A9C2EECE4E7F611B7523CEF4400C31E3F80B6512669455D402251FB593D8D58FABFC5F5BA30F6CB9B556CD7813B801D346FF26660B76B9950A5A49F9FE8047B1022C24FBBA9D7FEB7C61BF83B57E7C6A8A6150F04FB83F6D3C51EC3023554135A169132F675F3AE2B61D72AEFF22203199DD14801C7", 16)
		g, _ = new(big.Int).SetString("F7E1A085D69B3DDECBBCAB5C36B857B97994AFBBFA3AEA82F9574C0B3D0782675159578EBAD4594FE67107108180B449167123E84C281613B7CF09328CC8A6E13C167A8B547C8D28E0A3AE1E2BB3A675916EA37F0BFA213562F1FB627A01243BCCA4F1BEA8519089A883DFE15AE59F06928B665E807B552564014C3BFECF492A", 16)
	case "2048":
		p, _ = new(big.Int).SetString("95475cf5d93e596c3fcd1d902add02f427f5f3c7210313bb45fb4d5bb2e5fe1cbd678cd4bbdd84c9836be1f31c0777725aeb6c2fc38b85f48076fa76bcd8146cc89a6fb2f706dd719898c2083dc8d896f84062e2c9c94d137b054a8d8096adb8d51952398eeca852a0af12df83e475aa65d4ec0c38a9560d5661186ff98b9fc9eb60eee8b030376b236bc73be3acdbd74fd61c1d2475fa3077b8f080467881ff7e1ca56fee066d79506ade51edbb5443a563927dbc4ba520086746175c8885925ebc64c6147906773496990cb714ec667304e261faee33b3cbdf008e0c3fa90650d97d3909c9275bf4ac86ffcb3d03e6dfc8ada5934242dd6d3bcca2a406cb0b", 16)
		g, _ = new(big.Int).SetString("42debb9da5b3d88cc956e08787ec3f3a09bba5f48b889a74aaf53174aa0fbe7e3c5b8fcd7a53bef563b0e98560328960a9517f4014d3325fc7962bf1e049370d76d1314a76137e792f3f0db859d095e4a5b932024f079ecf2ef09c797452b0770e1350782ed57ddf794979dcef23cb96f183061965c4ebc93c9c71c56b925955a75f94cccf1449ac43d586d0beee43251b0b2287349d68de0d144403f13e802f4146d882e057af19b6f6275c6676c8fa0e3ca2713a3257fd1b27d0639f695e347d8d1cf9ac819a26ca9b04cb0eb9b7b035988d15bbac65212a55239cfc7e58fae38d7250ab9991ffbc97134025fe8ce04c4399ad96569be91a546f4978693c7a", 16)
	default:
		err = fmt.Errorf("invalid prime size")
	}
	return
}

// Setup function to calculate public key based on private key
func setup(privateKey *big.Int, g, p *big.Int) *big.Int {
	publicKey := new(big.Int).Exp(g, privateKey, p)
	return publicKey
}

type PublicKey struct {
	G, P, Y *big.Int
}

type PrivateKey struct {
	PublicKey
	X *big.Int
}

func encrypt(random io.Reader, pub *PublicKey, msg []byte) (ciphertext string, err error) {
	k, err := rand.Int(random, pub.P)
	if err != nil {
		return "", err
	}

	m := new(big.Int).SetBytes(msg)

	a := new(big.Int).Exp(pub.G, k, pub.P)
	s := new(big.Int).Exp(pub.Y, k, pub.P)
	b := s.Mul(s, m)
	b.Mod(b, pub.P)

	// Concatenate a and b as strings
	ciphertext = fmt.Sprintf("%X%X", a, b)

	return ciphertext, nil
}

func decrypt(priv *PrivateKey, ciphertext string) (msg []byte, err error) {
	// Parse the concatenated string into a and b strings
	if len(ciphertext)%2 != 0 {
		return nil, fmt.Errorf("invalid ciphertext format")
	}

	halfLen := len(ciphertext) / 2
	aHex := ciphertext[:halfLen]
	bHex := ciphertext[halfLen:]

	// Parse hexadecimal strings to big.Int
	a, successA := new(big.Int).SetString(aHex, 16)
	b, successB := new(big.Int).SetString(bHex, 16)
	if !successA || !successB {
		return nil, fmt.Errorf("invalid ciphertext format")
	}

	s := new(big.Int).Exp(a, priv.X, priv.P)
	s.ModInverse(s, priv.P)
	s.Mul(s, b)
	s.Mod(s, priv.P)
	em := s.Bytes()

	return em, nil
}

func main() {
	// Define command-line flags
	message := flag.String("message", "hello world", "Message to encrypt")
	privateKey := flag.String("privatekey", "40", "Private key value (x)")
	primeSize := flag.String("primesize", "1024", "Size of the prime number (512, 768, 1024)")
	decryptFlag := flag.Bool("decrypt", false, "Enable decryption")
	ciph := flag.String("ciphertext", "", "Ciphertext for decryption")
	calculatePublicKey := flag.Bool("setup", false, "Calculate public key only")
	publicKeyStr := flag.String("publickey", "", "Public key value (Y) for encryption")

	// Parse command-line flags
	flag.Parse()

	// Get g, p values based on prime size
	g, p, err := getGAndP(*primeSize)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Convert string to big.Int
	xval, ok := new(big.Int).SetString(*privateKey, 16)
	if !ok {
		fmt.Println("Error: Invalid private key value")
		return
	}

	if *calculatePublicKey {
		// Calculate public key only
		publicKey := setup(xval, g, p)
		fmt.Printf("Public Key (Y): %X\n", publicKey)
		return
	}

	// Calculate public key
	publicKey := setup(xval, g, p)

	// Create private key
	priv := &PrivateKey{
		PublicKey: PublicKey{
			G: g,
			P: p,
			Y: publicKey,
		},
		X: xval,
	}

	if !*decryptFlag {
		publicKeyVal, ok := new(big.Int).SetString(*publicKeyStr, 16)
		if !ok {
			fmt.Println("Error: Invalid public key value")
			return
		}
		pub := &PublicKey{
			G: g,
			P: p,
			Y: publicKeyVal,
		}

		// Encrypt the message
		messageBytes := []byte(*message)
		c, err := encrypt(rand.Reader, pub, messageBytes)
		if err != nil {
			fmt.Println("Error encrypting message:", err)
			return
		}

		// Print encrypted message
		fmt.Printf("%s\n", c)
	} else {
		// Decrypt the message
		ciphertext := *ciph
		message2, err := decrypt(priv, ciphertext)
		if err != nil {
			fmt.Println("Error decrypting message:", err)
			return
		}

		// Print decrypted message
		fmt.Printf("%s\n", string(message2))
	}
}
