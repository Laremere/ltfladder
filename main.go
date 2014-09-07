package main

import (
	"fmt"
	"github.com/yohcop/openid.go/src/openid"
	"log"
	"net/http"
)

var root = "vps.redig.us"

var staticDir = "/static/"
var staticRoot = root + staticDir

// For the demo, we use in-memory infinite storage nonce and discovery
// cache. In your app, do not use this as it will eat up memory and never
// free it. Use your own implementation, on a better database system.
// If you have multiple servers for example, you may need to share at least
// the nonceStore between them.
var nonceStore = &openid.SimpleNonceStore{
	Store: make(map[string][]*openid.Nonce)}
var discoveryCache = &openid.SimpleDiscoveryCache{}

func handler(rw http.ResponseWriter, req *http.Request) {
	fmt.Fprintln(rw, "Hello, "+req.URL.Path)
}

func main() {
	log.Println("Starting server.")
	http.HandleFunc("/", handler)
	http.Handle(staticDir,
		http.StripPrefix(staticDir, http.FileServer(http.Dir("./static/"))))

	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err)
	}
}
