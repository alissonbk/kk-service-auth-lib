package types

// This is compatible with Gin and Fiber (90% sure), need to check with other frameworks
type ContextWithHeader interface {
	GetHeader(s string) string
	JSON(int, interface{}) error
	Abort()
	Next()
}

type HandlerFunc func(ContextWithHeader)

// PublicKey can be one of each:
// publicKeyPath: path to a .pem file with the public key (will take current working dir as start point) (should start with /) example: /keys/pub.pem
// publicKeyString: a string containg the public key (file headers excluded for this)
// publicKeyFileBytes: the []byte from a file which has the key (formatted with the header)
type PublicKey struct {
	publicKeyPath      string
	publicKeyString    string
	publicKeyFileBytes []byte
}
