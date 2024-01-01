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
	key        = flag.String("key", "", "Public or Private key, depending on operation.")
	keygen     = flag.Bool("keygen", false, "Generate asymmetric keypair.")
	length     = flag.Int("bits", 0, "Key length. (for setup and wrapkey)")
	paramgen   = flag.Bool("setup", false, "Generate public params.")
	params     = flag.String("params", "", "ElGamal Public Parameters path.")
	priv       = flag.String("priv", "Private.pem", "Private key path.")
	pub        = flag.String("pub", "Public.pem", "Public key path.")
	pwd        = flag.String("pass", "", "Passphrase. (for Private key PEM encryption)")
	text       = flag.Bool("text", false, "Print keys contents.")
	unwrapkey  = flag.Bool("unwrapkey", false, "Unwrap symmetric key.")
	wrapkey    = flag.Bool("wrapkey", false, "Wrap symmetric key.")

)

func main() {
	// Parse command-line flags
	flag.Parse()

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage of", os.Args[0]+":")
		flag.PrintDefaults()
		os.Exit(3)
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
		pemBlock := &pem.Block{
			Type:  "ELGAMAL PRIVATE KEY",
			Bytes: priv.Bytes(),
		}

		// Codifica o bloco PEM em formato PEM
		pemData := pem.EncodeToMemory(pemBlock)
		fmt.Print(string(pemData))
		xval := new(big.Int).Set(priv)
		fmt.Println("PrivateKey(x):")
		x := fmt.Sprintf("%x", xval)
		splitz := SplitSubN(x, 2)
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
	readParams, err := readSchnorrParamsFromPEM(*params)
	if err != nil {
		fmt.Println("Error reading Schnorr parameters from PEM file:", err)
		return
	}

	if *text {
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

	var xval *big.Int
	var path string
	if *key == "" {
//			xval, err = generateRandomX(p)
		xval, err = generateRandomX(readParams.P)
		if err != nil {
			fmt.Println("Error generating x:", err)
			return
		}
		path, err = filepath.Abs(*priv)
		fmt.Printf("Private Key save to: %s\n", path)
		if err := savePrivateKeyToPEM(*priv, &PrivateKey{X: xval, PublicKey: PublicKey{G: readParams.G, P: readParams.P}}); err != nil {
			fmt.Println("Error saving private key:", err)
			return
		}
	} else {
		priv, err := readPrivateKeyFromPEM(*key)
		if err != nil {
			fmt.Println("Error reading private key:", err)
			return
		}
		xval = new(big.Int).Set(priv)
	}
	if *keygen {
		publicKey := setup(xval, readParams.G, readParams.P)
		path, err = filepath.Abs(*pub)
		fmt.Printf("Public Key save to: %s\n", path)
		if err := savePublicKeyToPEM(*pub, &PublicKey{Y: publicKey, G: readParams.G, P: readParams.P}); err != nil {
			fmt.Println("Error saving public key:", err)
			return
		}
		return
	}
	publicKey := setup(xval, readParams.G, readParams.P)
	priv := &PrivateKey{
		PublicKey: PublicKey{
			G: readParams.G,
			P: readParams.P,
			Y: publicKey,
		},
		X: xval,
	}
	if *unwrapkey {
		ciphertext := *cph
		message, err := decrypt(priv, ciphertext)
		if err != nil {
			fmt.Println("Error decrypting message:", err)
			return
		}
		fmt.Printf("Shared= %x\n", message)
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

func savePrivateKeyToPEM(fileName string, priv *PrivateKey) error {
	privBytes := priv.X.Bytes()

	block := &pem.Block{
		Type:  "ELGAMAL PRIVATE KEY",
		Bytes: privBytes,
	}

	return savePEMToFile(fileName, block, *pwd != "")
}

func readPrivateKeyFromPEM(fileName string) (*big.Int, error) {
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

	// Check if the PEM block is encrypted
	if block.Headers["Proc-Type"] == "4,ENCRYPTED" {
		// Decrypt private key if key is provided
		if *pwd == "" {
			return nil, fmt.Errorf("private key is encrypted, but no decryption key provided")
		}

		privBytes, err := decryptBlock(block, deriveKeyFromPassword(*pwd))
		if err != nil {
			return nil, err
		}
		return new(big.Int).SetBytes(privBytes), nil
	}

	return new(big.Int).SetBytes(block.Bytes), nil
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
			"DEK-Info":  fmt.Sprintf("%s,%s", strings.ToUpper(*cph), nonceHex),
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
