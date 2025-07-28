package types

// This is compatible with Gin and Fiber (90% sure), need to check with other frameworks
type ContextWithHeader interface {
	GetHeader(s string) string
	JSON(int, interface{}) error
	Abort()
	Next()
}

type HandlerFunc func(ContextWithHeader)
