# elgamal
### ElGamal Cryptosystem Command-line Tool written in Go
The ElGamal algorithm is a public-key cryptography system that enables secure communication between two parties, involving key generation and cryptographic operations. Initially, a large prime number (p) and a generator (g) for a finite cyclic group are generated. Each entity possesses a private key (x), kept secret, and a public key (Y), derived from g^x mod p. To encrypt a message, the sender generates a random session key, computes two components (a and b), and sends (g^k mod p, Y^k * message mod p) to the recipient. The recipient, using their private key, decrypts the message. The ElGamal algorithm is known for its security based on the difficulty of solving the discrete logarithm problem and provides confidentiality and authentication properties.

## Usage
```
Usage of elgamal:
  -bits int
        Key length. (for setup and wrapkey)
  -cipher string
        Ciphertext to unwrap.
  -key string
        Public or Private key, depending on operation.
  -keygen
        Generate asymmetric keypair.
  -params string
        ElGamal Public Parameters path.
  -pass string
        Passphrase. (for Private key PEM encryption)
  -priv string
        Private key path. (default "Private.pem")
  -pub string
        Public key path. (default "Public.pem")
  -setup
        Generate public params.
  -text
        Print keys contents.
  -unwrapkey
        Unwrap symmetric key.
  -wrapkey
        Wrap symmetric key.
```

## Example
- **Generate Public Parameters**
```
go run elgamal.go -setup -bits 2048 > SchnorrParams.pem
```
- **Generate Asymmetric Keypair**
```
go run elgamal.go -keygen -params SchnorrParams.pem -priv Private.pem -pass <passphrase> -pub Public.pem
```
- **Wrap a Symmetric Key**
```
go run elgamal.go -wrapkey -key Public.pem
```
- **Unwrap a Symmetric Key**
```
go run elgamal.go -unwrapkey -params SchnorrParams.pem -key Private.pem -cipher <ciphertext>
```
- **Display Key Contents**
```
go run elgamal.go -text -key Private.pem -pass <passphrase>
go run elgamal.go -text -key Public.pem
go run elgamal.go -text -params SchnorrParams.pem
```
## License
This project is licensed under the ISC License.

##### Copyright (c) 2020-2024 Pedro F. Albanese - ALBANESE Research Lab.
