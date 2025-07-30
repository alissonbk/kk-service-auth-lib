package main

import "github.com/alissonbk/kk-service-auth-lib/auth"

func main() {
	auth.AuthRequired(&auth.PublicKey{PublicKeyPath: ""})
}
