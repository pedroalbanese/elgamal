package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

var (
	cph        = flag.String("cipher", "", "Ciphertext to unwrap.")
	key        = flag.String("key", "", "Public or private key, depending on operation.")
	keygen     = flag.Bool("keygen", false, "Generate asymmetric keypair.")
	length     = flag.Int("bits", 0, "Key length. (for setup and wrapkey)")
	modulus    = flag.Bool("modulus", false, "Display the public key modulus.")
	paramgen   = flag.Bool("setup", false, "Generate public params.")
	params     = flag.String("params", "", "ElGamal public parameters path.")
	priv       = flag.String("priv", "Private.pem", "Private key path.")
	pub        = flag.String("pub", "Public.pem", "Public key path.")
	pwd        = flag.String("pass", "", "Passphrase. (for Private key PEM encryption)")
	sig        = flag.String("signature", "", "Signature.")
	sign       = flag.Bool("sign", false, "Sign message with private key.")
	text       = flag.Bool("text", false, "Print keys contents.")
	unwrapkey  = flag.Bool("unwrapkey", false, "Unwrap symmetric key with private key.")
	verify     = flag.Bool("verify", false, "Verify signature with public key.")
	wrapkey    = flag.Bool("wrapkey", false, "Wrap symmetric key with public key.")
)

func main() {
	// Parse command-line flags
	flag.Parse()

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage of", os.Args[0]+":")
		flag.PrintDefaults()
		os.Exit(3)
	}

	var inputfile io.Reader
	var err error
	if *sign || *verify {
		inputfile, err = os.Open(flag.Arg(0))
		if err != nil {
			log.Fatalf("failed opening file: %s", err)
		}
	}

	if *paramgen {
		if *length == 0 {
			*length = 2048
		}
		setParams, err := generateSchnorrGroup()
		err = saveSchnorrParamsToPEM(*params, setParams)
		if err != nil {
			log.Fatal("Error saving Schnorr parameters to PEM file:", err)
			return
		}
		os.Exit(0)
	}
	var blockType string
	if *key != "" {
		pemData, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println("Error reading PEM file:", err)
			return
		}
		block, _ := pem.Decode(pemData)
		if block == nil {
			fmt.Println("Error decoding PEM block")
			return
		}
		blockType = block.Type
	}
	if *text && *key != "" && blockType == "ELGAMAL PRIVATE KEY" {
		priv, err := readPrivateKeyFromPEM(*key)
		if err != nil {
			fmt.Println("Error reading private key:", err)
			return
		}
		privPEM := &PrivateKey{
			X: priv.X,
			P: priv.P,
			G: priv.G,
		}

		privBytes, err := encodePrivateKeyPEM(privPEM)
		if err != nil {
			return
		}
		pemBlock := &pem.Block{
			Type:  "ELGAMAL PRIVATE KEY",
			Bytes: privBytes,
		}

		pemData := pem.EncodeToMemory(pemBlock)
		fmt.Print(string(pemData))
		xval := new(big.Int).Set(priv.X)
		fmt.Println("PrivateKey(x):")
		x := fmt.Sprintf("%x", xval)
		splitz := SplitSubN(x, 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("    %-10s    \n", strings.ReplaceAll(chunk, " ", ":"))
		}
		fmt.Println("Prime(p):")
		p := fmt.Sprintf("%x", priv.P)
		splitz = SplitSubN(p, 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("    %-10s    \n", strings.ReplaceAll(chunk, " ", ":"))
		}
		fmt.Println("Generatot(g):")
		g := fmt.Sprintf("%x", priv.G)
		splitz = SplitSubN(g, 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("    %-10s    \n", strings.ReplaceAll(chunk, " ", ":"))
		}
		fmt.Println("PublicKey(y):")
		publicKey := setup(priv.X, priv.G, priv.P)
		pub := fmt.Sprintf("%x", publicKey)
		splitz = SplitSubN(pub, 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("    %-10s    \n", strings.ReplaceAll(chunk, " ", ":"))
		}
		os.Exit(0)
	}
	if *text && *key != "" && blockType == "ELGAMAL PUBLIC KEY" {
		pemData, err := ioutil.ReadFile(*key)
		if err != nil {
			fmt.Println("Error reading PEM file:", err)
			return
		}
		fmt.Print(string(pemData))
		publicKeyVal, err := readPublicKeyFromPEM(*key)
		if err != nil {
			fmt.Println("Error: Invalid public key value")
			return
		}
		fmt.Println("Public Key Parameters:")
		fmt.Println("Prime(p):")
		p := fmt.Sprintf("%x", publicKeyVal.P)
		splitz := SplitSubN(p, 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("    %-10s    \n", strings.ReplaceAll(chunk, " ", ":"))
		}
		fmt.Println("Generator(g):")
		g := fmt.Sprintf("%x", publicKeyVal.G)
		splitz = SplitSubN(g, 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("    %-10s    \n", strings.ReplaceAll(chunk, " ", ":"))
		}
		fmt.Println("PublicKey(y):")
		y := fmt.Sprintf("%x", publicKeyVal.Y)
		splitz = SplitSubN(y, 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("    %-10s    \n", strings.ReplaceAll(chunk, " ", ":"))
		}
		return
	}
	if *modulus && blockType == "ELGAMAL PRIVATE KEY" {
		privKey, err := readPrivateKeyFromPEM(*key)
		if err != nil {
			fmt.Println("Error reading private key:", err)
			return
		}
		publicKey := setup(privKey.X, privKey.G, privKey.P)
		fmt.Printf("Y=%X\n", publicKey)
		return
	}
	if *modulus && blockType == "ELGAMAL PUBLIC KEY" {
		publicKey, err := readPublicKeyFromPEM(*key)
		if err != nil {
			fmt.Println("Error reading public key:", err)
			return
		}
		fmt.Printf("Y=%X\n", publicKey.Y)
		return
	}
	if *wrapkey {
		if *length == 0 {
			*length = 256
		}
		publicKeyVal, err := readPublicKeyFromPEM(*key)
		if err != nil {
			fmt.Println("Error: Invalid public key value")
			return
		}

		// Assuming readParams is of type SchnorrParams
		pub := &PublicKey{
			G: publicKeyVal.G,
			P: publicKeyVal.P,
			Y: publicKeyVal.Y,
		}

		messageBytes := make([]byte, *length/8)
		_, err = rand.Read(messageBytes)
		if err != nil {
			fmt.Println("Error generating random key:", err)
			return
		}
		c, err := encrypt(rand.Reader, pub, messageBytes)
		if err != nil {
			fmt.Println("Error encrypting message:", err)
			return
		}

		fmt.Printf("Cipher= %s\n", c)
		fmt.Printf("Shared= %x\n", messageBytes)
		os.Exit(0)
	}
	if *unwrapkey {
		if *key == "" {
			fmt.Println("Error: Private key file not provided for unwrapping.")
			return
		}

		priv, err := readPrivateKeyFromPEM(*key)
		if err != nil {
			fmt.Println("Error reading private key:", err)
			return
		}

		ciphertext := *cph
		message, err := decrypt(priv, ciphertext)
		if err != nil {
			fmt.Println("Error decrypting message:", err)
			return
		}
		fmt.Printf("Shared= %x\n", message)
	}
	if *text {
		readParams, err := readSchnorrParamsFromPEM(*params)
		if err != nil {
			fmt.Println("Error reading Schnorr parameters from PEM file:", err)
			return
		}

		pemData, err := ioutil.ReadFile(*params)
		if err != nil {
			fmt.Println("Error reading PEM file:", err)
			return
		}
		fmt.Print(string(pemData))
		fmt.Println("Schnorr Parameters:")
		fmt.Println("Prime(p):")
		p := fmt.Sprintf("%x", readParams.P)
		splitz := SplitSubN(p, 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("    %-10s    \n", strings.ReplaceAll(chunk, " ", ":"))
		}
		fmt.Println("Order(q):")
		q := fmt.Sprintf("%x", readParams.Q)
		splitz = SplitSubN(q, 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("    %-10s    \n", strings.ReplaceAll(chunk, " ", ":"))
		}
		fmt.Println("Generator(g):")
		g := fmt.Sprintf("%x", readParams.G)
		splitz = SplitSubN(g, 2)
		for _, chunk := range split(strings.Trim(fmt.Sprint(splitz), "[]"), 45) {
			fmt.Printf("    %-10s    \n", strings.ReplaceAll(chunk, " ", ":"))
		}
		os.Exit(0)
	}
	if *keygen {
		var xval *big.Int
		var path string

		readParams, err := readSchnorrParamsFromPEM(*params)
		if err != nil {
			log.Fatal("Error reading Schnorr parameters from PEM file:", err)
			return
		}

		if *key == "" {
			xval, err = generateRandomX(readParams.P)
			if err != nil {
				log.Fatal("Error generating x:", err)
				return
			}
			path, err = filepath.Abs(*priv)
			fmt.Printf("Private Key save to: %s\n", path)
			privateKey := &PrivateKey{
				X: xval,
				P: readParams.P,
				G: readParams.G,
			}
			if err := savePrivateKeyToPEM(*priv, privateKey); err != nil {
				log.Fatal("Error saving private key:", err)
				return
			}
		} else {
			priv, err := readPrivateKeyFromPEM(*key)
			if err != nil {
				log.Fatal("Error reading private key:", err)
				return
			}
			xval = new(big.Int).Set(priv.X)
		}

		publicKey := setup(xval, readParams.G, readParams.P)

		path, err = filepath.Abs(*pub)
		fmt.Printf("Public Key save to: %s\n", path)
		if err := savePublicKeyToPEM(*pub, &PublicKey{Y: publicKey, G: readParams.G, P: readParams.P}); err != nil {
			log.Fatal("Error saving public key:", err)
			return
		}

		return
	}
	if *sign {
		message, err := ioutil.ReadAll(inputfile)
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}

		priv, err := readPrivateKeyFromPEM(*key)
		if err != nil {
			fmt.Println("Error reading private key:", err)
			return
		}

		sign, err := signElGamal(priv, message)
		if err != nil {
			log.Fatal("Error signing message:", err)
			return
		}

		fmt.Println("Sign=", sign)
	}
	if *verify {
		message, err := ioutil.ReadAll(inputfile)
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}

		if *key == "" {
			fmt.Println("Error: Public key file not provided for verification.")
			return
		}

		publicKeyVal, err := readPublicKeyFromPEM(*key)
		if err != nil {
			fmt.Println("Error: Invalid public key value")
			return
		}

		pub := &PublicKey{
			G: publicKeyVal.G,
			P: publicKeyVal.P,
			Y: publicKeyVal.Y,
		}

		isValid := verifyElGamal(pub, message, *sig)
		fmt.Println("Signature verification:", isValid)
	}
}


func setup(privateKey *big.Int, g, p *big.Int) *big.Int {
	publicKey := new(big.Int).Exp(g, privateKey, p)
	return publicKey
}

type PublicKey struct {
	G, P, Y *big.Int
}

type PrivateKey struct {
	PublicKey
	P *big.Int
	G *big.Int
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

	aHex := fmt.Sprintf("%0*x", (pub.P.BitLen())/4, a)
	bHex := fmt.Sprintf("%0*x", (pub.P.BitLen())/4, b)

	ciphertext = aHex + bHex

	return ciphertext, nil
}

func decrypt(priv *PrivateKey, ciphertext string) (msg []byte, err error) {
	if len(ciphertext)%2 != 0 {
		return nil, fmt.Errorf("invalid ciphertext format")
	}

	halfLen := len(ciphertext) / 2
	aHex := ciphertext[:halfLen]
	bHex := ciphertext[halfLen:]

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

// Sign a message using ElGamal with a specified hash function
func signElGamal(privateKey *PrivateKey, message []byte) (signature string, err error) {
	for {
		// Choose a random value k in the range [1, p-2]
		k, err := rand.Int(rand.Reader, new(big.Int).Sub(privateKey.P, big.NewInt(2)))
		if err != nil {
			return "", fmt.Errorf("failed to generate random number: %v", err)
		}

		// Ensure k is not zero
		if k.Sign() == 0 {
			k = big.NewInt(1)
		}

		// Check if k is relatively prime to (p-1)
		if new(big.Int).GCD(nil, nil, k, new(big.Int).Sub(privateKey.P, big.NewInt(1))).Cmp(big.NewInt(1)) == 0 {
			// Compute r = g^k mod p
			rBigInt := new(big.Int).Exp(privateKey.G, k, privateKey.P)
			rBigInt.Mod(rBigInt, privateKey.P)
			rHex := fmt.Sprintf("%x", rBigInt)

			// Compute hash of the message using the specified hash function
			hash := sha256.Sum256(message)
			hashInt := new(big.Int).SetBytes(hash[:])

			// Ensure kInv is not zero
			kInv := new(big.Int).ModInverse(k, new(big.Int).Sub(privateKey.P, big.NewInt(1)))
			if kInv == nil {
				return "", errors.New("failed to calculate modular inverse: k is not invertible")
			}

			// Compute s = (k^-1 * (hash(message) - x*r)) mod (p-1)
			sBigInt := new(big.Int).Mul(kInv, new(big.Int).Sub(hashInt, new(big.Int).Mul(privateKey.X, rBigInt)))
			sBigInt.Mod(sBigInt, new(big.Int).Sub(privateKey.P, big.NewInt(1)))
			sHex := fmt.Sprintf("%x", sBigInt)

			// Ensure R and S have the same length as P by padding with zeros
			rHex = strings.TrimLeft(rHex, "0")
			sHex = strings.TrimLeft(sHex, "0")
			paddingLen := len(fmt.Sprintf("%x", privateKey.P))
			rPadded := fmt.Sprintf("%0*s", paddingLen, rHex)
			sPadded := fmt.Sprintf("%0*s", paddingLen, sHex)

			signature = rPadded + sPadded
			return signature, nil
		}
	}
}

// Verify ElGamal signature with a specified hash function
func verifyElGamal(publicKey *PublicKey, message []byte, signature string) bool {
	// Determine the length of P and extract R and S from the signature
	pLength := len(fmt.Sprintf("%X", publicKey.P))
	if len(signature) != 2*pLength {
		return false
	}

	rHex := signature[:pLength]
	sHex := signature[pLength:]

	// Convert R and S from hex to big integers
	r, ok := new(big.Int).SetString(rHex, 16)
	if !ok {
		fmt.Println("Error converting R string to big.Int")
		return false
	}

	s, ok := new(big.Int).SetString(sHex, 16)
	if !ok {
		fmt.Println("Error converting S string to big.Int")
		return false
	}

	// Check if R and S are in the range [1, p-1]
	if r.Cmp(big.NewInt(1)) == -1 || r.Cmp(new(big.Int).Sub(publicKey.P, big.NewInt(1))) == 1 {
		return false
	}
	if s.Cmp(big.NewInt(1)) == -1 || s.Cmp(new(big.Int).Sub(publicKey.P, big.NewInt(1))) == 1 {
		return false
	}

	// Compute g^hash(message) mod p using the specified hash function
	hash := sha256.Sum256(message)
	hashInt := new(big.Int).SetBytes(hash[:])
	ghash := new(big.Int).Exp(publicKey.G, hashInt, publicKey.P)

	// Compute y^r * r^s mod p
	yr := new(big.Int).Exp(publicKey.Y, r, publicKey.P)
	rs := new(big.Int).Exp(r, s, publicKey.P)
	yrrs := new(big.Int).Mul(yr, rs)
	yrrs.Mod(yrrs, publicKey.P)

	// Check if g^hash(message) == y^r * r^s mod p
	return ghash.Cmp(yrrs) == 0
}

func savePrivateKeyToPEM(fileName string, privKey *PrivateKey) error {
	privPEM := &PrivateKey{
		X: privKey.X,
		P: privKey.P,
		G: privKey.G,
	}

	privBytes, err := encodePrivateKeyPEM(privPEM)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "ELGAMAL PRIVATE KEY",
		Bytes: privBytes,
	}

	return savePEMToFile(fileName, block, *pwd != "")
}

func encodePrivateKeyPEM(privPEM *PrivateKey) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(privPEM)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func readPrivateKeyFromPEM(fileName string) (*PrivateKey, error) {
	pemData, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	if block.Type != "ELGAMAL PRIVATE KEY" {
		return nil, errors.New("unexpected PEM block type")
	}

	if block.Headers["Proc-Type"] == "4,ENCRYPTED" {
		if *pwd == "" {
			return nil, fmt.Errorf("private key is encrypted, but no decryption key provided")
		}

		privBytes, err := decryptBlock(block, deriveKeyFromPassword(*pwd))
		if err != nil {
			return nil, err
		}

		var privKey PrivateKey
		buf := bytes.NewReader(privBytes)
		dec := gob.NewDecoder(buf)
		err = dec.Decode(&privKey)
		if err != nil {
			return nil, err
		}

		return &privKey, nil
	}

	var privKey PrivateKey
	buf := bytes.NewReader(block.Bytes)
	dec := gob.NewDecoder(buf)
	err = dec.Decode(&privKey)
	if err != nil {
		return nil, err
	}

	return &privKey, nil
}

func savePublicKeyToPEM(fileName string, pub *PublicKey) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	// Encode the public key parameters to gob
	pubBytes, err := publicKeyToBytes(pub)
	if err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "ELGAMAL PUBLIC KEY",
		Bytes: pubBytes,
	}

	err = pem.Encode(file, block)
	if err != nil {
		return err
	}

	return nil
}

func readPublicKeyFromPEM(fileName string) (*PublicKey, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	pemData, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Decode the public key parameters from gob
	pub, err := bytesToPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return pub, nil
}

func publicKeyToBytes(pub *PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("cannot encode nil PublicKey pointer")
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(pub)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func bytesToPublicKey(data []byte) (*PublicKey, error) {
	var pub PublicKey
	dec := gob.NewDecoder(bytes.NewReader(data))

	err := dec.Decode(&pub)
	if err != nil {
		return nil, err
	}

	return &pub, nil
}

func generateRandomX(p *big.Int) (*big.Int, error) {
	x, err := rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(2)))
	if err != nil {
		return nil, err
	}
	return x, nil
}

// isPrime checks if a number is prime.
func isPrime(n *big.Int) bool {
	return n.ProbablyPrime(20)
}

// generatePrime generates a prime number with exactly n bits.
func generatePrime(length int) (*big.Int, error) {
	for {
		// Generate a random number with at least n bits
		randomBits := make([]byte, length/8)
		_, err := rand.Read(randomBits)
		if err != nil {
			return nil, err
		}

		// Set the most significant and least significant bits to ensure an odd number
		randomBits[0] |= 1
		randomBits[len(randomBits)-1] |= 1

		// Create a big integer from the generated bytes
		prime := new(big.Int).SetBytes(randomBits)

		// Truncate to exactly n bits
		prime.SetBit(prime, length-1, 1)

		// Check if the generated number is prime and has exactly n bits
		if isPrime(prime) && prime.BitLen() == length {
			return prime, nil
		}

		// Print a dot to the console every second
		print(".")
	}
}

func generateSchnorrGroup() (*SchnorrParams, error) {
	// Desired size for q (order)
	qSize := *length - 1

	// Generate the prime number q (order) with exactly qSize bits
	q, err := generatePrime(256)
	if err != nil {
		return nil, fmt.Errorf("error generating q: %v", err)
	}

	// Validate the bit length of q
	if q.BitLen() != 256 {
		return nil, errors.New("generated q does not have the desired length")
	}

	// Generate the large prime number p = qr + 1 with exactly qSize bits
	p, err := generatePrime(qSize+1)
	if err != nil {
		return nil, fmt.Errorf("error generating p: %v", err)
	}

	// Validate the bit length of p
	if p.BitLen() != (qSize + 1) {
		return nil, errors.New("generated p does not have the desired length")
	}

	// Calculate r such that p = qr + 1
	r := new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), q)

	// Choose an h in the range 1 < h < p
	var h *big.Int
	for {
		h, _ = rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(2)))
		h.Add(h, big.NewInt(1))
		if h.Cmp(big.NewInt(1)) == 1 && h.Cmp(p) == -1 {
			break
		}
	}

	// Calculate g = h^r mod p
	g := new(big.Int).Exp(h, r, p)

	return &SchnorrParams{
		P: p,
		Q: q,
		G: g,
	}, nil
}


// SchnorrParams represents Schnorr group parameters.
type SchnorrParams struct {
	P *big.Int
	Q *big.Int
	G *big.Int
}

func init() {
	// Register SchnorrParams with the gob package
	gob.Register(&SchnorrParams{})
}

// paramsToBytes encodes SchnorrParams to bytes.
func paramsToBytes(params *SchnorrParams) ([]byte, error) {
	if params == nil {
		return nil, errors.New("cannot encode nil SchnorrParams pointer")
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(params)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// bytesToParams decodes bytes to SchnorrParams.
func bytesToParams(data []byte) (*SchnorrParams, error) {
	var params SchnorrParams
	dec := gob.NewDecoder(bytes.NewReader(data))

	err := dec.Decode(&params)
	if err != nil {
		return nil, err
	}

	return &params, nil
}

// Save Schnorr parameters to a single PEM file or stdout
func saveSchnorrParamsToPEM(fileName string, params *SchnorrParams) error {
	var file *os.File
	var err error

	print("\n")
	if fileName == "" {
		// If fileName is empty, write to stdout
		file = os.Stdout
	} else {
		// Otherwise, open the specified file
		file, err = os.Create(fileName)
		if err != nil {
			return err
		}
		defer file.Close()
	}

	// Get the Schnorr parameters bytes
	paramsBytes, err := paramsToBytes(params)
	if err != nil {
		return err
	}

	// Write the Schnorr parameters to a single PEM block
	err = pem.Encode(file, &pem.Block{
		Type:  "SCHNORR PARAMETERS",
		Bytes: paramsBytes,
	})
	if err != nil {
		return err
	}

	return nil
}

// readSchnorrParamsFromPEM reads Schnorr parameters from a PEM file.
func readSchnorrParamsFromPEM(fileName string) (*SchnorrParams, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	pemData, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	return bytesToParams(block.Bytes)
}

func savePEMToFile(fileName string, block *pem.Block, isPrivateKey bool) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	if isPrivateKey && *pwd != "" {
		key := deriveKeyFromPassword(*pwd)
		encryptedBlock := encryptBlock(block, key)
		block = encryptedBlock
	}

	err = pem.Encode(file, block)
	if err != nil {
		return err
	}

	return nil
}

func readKeyFromPEM(fileName string, isPrivateKey bool) ([]byte, error) {
	fileData, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(fileData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if isPrivateKey && *pwd != "" {
		key := deriveKeyFromPassword(*pwd)
		bytes, err := decryptBlock(block, key)
		if err != nil {
			return nil, err
		}
		return bytes, nil
	}

	return block.Bytes, nil
}

func deriveKeyFromPassword(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

func encryptBlock(block *pem.Block, key []byte) *pem.Block {
	blockBytes := block.Bytes

	var blockCipher cipher.Block
	var err error

	blockCipher, err = aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	gcm, _ := cipher.NewGCM(blockCipher)

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err.Error())
	}

	nonceHex := hex.EncodeToString(nonce)
	encryptedBytes := gcm.Seal(nil, nonce, blockBytes, nil)

	newBlock := &pem.Block{
		Type:  block.Type,
		Bytes: encryptedBytes,
		Headers: map[string]string{
			"Proc-Type": "4,ENCRYPTED",
			"DEK-Info":  fmt.Sprintf("%s,%s", "AES", nonceHex),
		},
	}
	return newBlock
}

func decryptBlock(block *pem.Block, key []byte) ([]byte, error) {
	blockBytes := block.Bytes

	dekInfo, ok := block.Headers["DEK-Info"]
	if !ok {
		return nil, fmt.Errorf("missing DEK-Info in PEM block header")
	}

	dekInfoParts := strings.Split(dekInfo, ",")
	if len(dekInfoParts) != 2 {
		return nil, fmt.Errorf("invalid DEK-Info format")
	}

	var blockCipher cipher.Block
	var err error

	blockCipher, err = aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, _ := cipher.NewGCM(blockCipher)

	nonceHex := dekInfoParts[1]
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %v", err)
	}

	decryptedBytes, err := gcm.Open(nil, nonce, blockBytes, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt PEM block: %v", err)
	}

	return decryptedBytes, nil
}

func SplitSubN(s string, n int) []string {
	sub := ""
	subs := []string{}

	runes := bytes.Runes([]byte(s))
	l := len(runes)
	for i, r := range runes {
		sub = sub + string(r)
		if (i+1)%n == 0 {
			subs = append(subs, sub)
			sub = ""
		} else if (i + 1) == l {
			subs = append(subs, sub)
		}
	}

	return subs
}

func split(s string, size int) []string {
	ss := make([]string, 0, len(s)/size+1)
	for len(s) > 0 {
		if len(s) < size {
			size = len(s)
		}
		ss, s = append(ss, s[:size]), s[size:]

	}
	return ss
}
