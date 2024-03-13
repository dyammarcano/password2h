package password2h

import (
	"bytes"
	"crypto/rand"
	"errors"
	"github.com/dyammarcano/base58"
	"golang.org/x/crypto/argon2"
)

type (
	HashSalt struct {
		Hash, Salt []byte
	}

	Argon2idHash struct {
		// time represents the number of
		// passed over the specified memory.
		time uint32

		// cpu memory to be used.
		memory uint32

		// threads for parallelism aspect
		// of the algorithm.
		threads uint8

		// keyLen of the generate hash key.
		keyLen uint32

		// saltLen the length of the salt used.
		saltLen uint32
	}
)

// NewArgon2idHash constructor function for
// Argon2idHash.
func NewArgon2idHash(time, saltLen uint32, memory uint32, threads uint8, keyLen uint32) *Argon2idHash {
	return &Argon2idHash{
		time:    time,
		saltLen: saltLen,
		memory:  memory,
		threads: threads,
		keyLen:  keyLen,
	}
}

// NewArgon2idHashDefault constructor function for
// Argon2idHash.
func NewArgon2idHashDefault() *Argon2idHash {
	return NewArgon2idHash(1, 20, 64*1024, 32, 40)
}

func (a *Argon2idHash) generateHash(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, a.time, a.memory, a.threads, a.keyLen)
}

// HashPassword create hash from password
func (a *Argon2idHash) HashPassword(password string) *HashSalt {
	salt := make([]byte, a.saltLen)
	_, _ = rand.Read(salt)

	return &HashSalt{Hash: a.generateHash(password, salt), Salt: salt}
}

// CompareHashAndPassword return true if hash is equal to password
func (a *Argon2idHash) CompareHashAndPassword(encodedHash, password string) bool {
	data, err := a.UnwrapPassword(encodedHash)
	if err != nil {
		return false
	}

	return bytes.Equal(a.generateHash(password, data.Salt), data.Hash)
}

// WrapPassword wrap password and salt from object
func (a *Argon2idHash) WrapPassword(data *HashSalt) string {
	var response bytes.Buffer
	response.Write(data.Hash)
	response.Write(data.Salt)

	return base58.StdEncoding.EncodeToString(response.Bytes())
}

// UnwrapPassword unwrap password and salt into object
func (a *Argon2idHash) UnwrapPassword(encodedData string) (*HashSalt, error) {
	data, err := base58.StdEncoding.DecodeString(encodedData)
	if err != nil {
		return nil, err
	}

	// Check if the decoded data has at least the length of hash and salt
	if len(data) < int(a.keyLen) {
		return nil, errors.New("invalid encoded data")
	}

	return &HashSalt{Hash: data[:a.keyLen], Salt: data[a.keyLen : a.keyLen+a.saltLen]}, nil
}
