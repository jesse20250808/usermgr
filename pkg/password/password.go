package password

import "golang.org/x/crypto/bcrypt"

// Hash returns a bcrypt hash of the plaintext password.
func Hash(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	return string(b), err
}

// Verify compares a bcrypt hash with a plaintext password.
func Verify(hash, plain string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain))
}
