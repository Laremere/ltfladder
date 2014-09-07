package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/yohcop/openid.go/src/openid"
	"log"
	"net/http"
)

var root = "http://vps.redig.us"

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

func IndexHandler(rw http.ResponseWriter, req *http.Request) {
	fmt.Fprintln(rw, "Hello, "+req.URL.Path)
}

func LoginHandler(rw http.ResponseWriter, req *http.Request) {
	url, err := openid.RedirectUrl("http://steamcommunity.com/openid",
		root+"/openidcallback", root)
	if err != nil {
		http.Error(rw, "Error with openID redirect", http.StatusInternalServerError)
		return
	}
	http.Redirect(rw, req, url, 303)
}

func AuthenticateHandler(rw http.ResponseWriter, req *http.Request) {
	id, err := openid.Verify(
		root+req.URL.String(),
		discoveryCache, nonceStore)
	if err != nil {
		http.Error(rw, "Error with openID authentication", http.StatusInternalServerError)
		return
	}

	var authtoken string
	{
		var buffer bytes.Buffer

		if err != nil {
			http.Error(rw, "Error generating auth token"+err.Error(), http.StatusInternalServerError)
			return
		}
		authtoken = string(bytes)
	}

	fmt.Fprintln(rw, id)
	fmt.Fprintln(rw, authtoken)
}

// func logUsers(db *sql.DB) {
// 	rows, err := db.Query("Select steamname from users")
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer rows.Close()
// 	for rows.Next() {
// 		var name string
// 		if err := rows.Scan(&name); err != nil {
// 			log.Fatal(err)
// 		}
// 		log.Println(name)
// 	}
// 	if err := rows.Err(); err != nil {
// 		log.Fatal(err)
// 	}
// }

var db, dbErr = sql.Open("mysql", "root:root@/ltfladder")

func main() {
	log.Println("Starting server.")

	//Test db connection
	if dbErr != nil {
		log.Fatal(dbErr)
	}
	err := db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	//Initialize http handlers
	http.HandleFunc("/", IndexHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/openidcallback", AuthenticateHandler)
	http.Handle(staticDir,
		http.StripPrefix(staticDir, http.FileServer(http.Dir("./static/"))))

	log.Fatal(http.ListenAndServe(":8080", nil))
}

type userID int64

func (id *userID) Valid() bool {
	return *id > 0
}

func authenticate(req *http.Request) (userID, error) {
	return 0, nil
}
