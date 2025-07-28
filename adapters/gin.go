package adapters

import (
	"context"

	"github.com/alissonbk/kk-service-auth-lib/types"
	"github.com/gin-gonic/gin"
)

/*
* Supports using the types.HandlerFunc with gin
 */
func GinAdapter(handlerFunc types.HandlerFunc) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		handlerFunc(NewGinContextAdapter(ctx))
	}
}

type GinContextAdapter struct {
	*gin.Context
}

func NewGinContextAdapter(ctx *gin.Context) *GinContextAdapter {
	return &GinContextAdapter{ctx}
}

func (g *GinContextAdapter) GetHeader(s string) string {
	return g.Request.Header.Get(s)
}

// Most frameworks implement this returning error...
func (g *GinContextAdapter) JSON(code int, obj interface{}) error {
	g.Context.JSON(code, obj)
	return nil
}

func (g *GinContextAdapter) Abort() {
	g.Context.Abort() // Using the pointer receiver
}

func (g *GinContextAdapter) Next() {
	g.Context.Next()
}

func (g *GinContextAdapter) RequestContext() context.Context {
	return g.Request.Context()
}
