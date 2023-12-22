# elgamal
### ElGamal Cryptosystem Command-line Tool written in Go
The ElGamal algorithm is a public-key cryptography system that enables secure communication between two parties, involving key generation and cryptographic operations. Initially, a large prime number (p) and a generator (g) for a finite cyclic group are generated. Each entity possesses a private key (x), kept secret, and a public key (Y), derived from g^x mod p. To encrypt a message, the sender generates a random session key, computes two components (a and b), and sends (g^k mod p, Y^k * message mod p) to the recipient. The recipient, using their private key, decrypts the message. The ElGamal algorithm is known for its security based on the difficulty of solving the discrete logarithm problem and provides confidentiality and authentication properties.

## Usage
```
Usage of elgamal:
  -ciphertext string
        Ciphertext for decryption
  -decrypt
        Enable decryption
  -message string
        Message to encrypt
  -primesize string
        Size of the prime number (512, 768, 1024) (default "1024")
  -privatekey string
        Private key value (x) (default "40")
  -publickey string
        Public key value (Y) for encryption
  -setup
        Calculate public key only
```

## License
This project is licensed under the ISC License.

##### Copyright (c) 2020-2024 Pedro F. Albanese - ALBANESE Research Lab.
