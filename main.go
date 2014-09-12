package main

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/yohcop/openid.go/src/openid"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"
)

var root = "https://vps.redig.us"
var rawroot = "vps.redig.us" //no https

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

func IndexHandler(w http.ResponseWriter, req *http.Request) {
	user, err := authenticate(req)
	if err != nil {
		http.Error(w, "Login error", http.StatusInternalServerError)
		log.Println("authenticate error", err)
		return
	}
	if user == nil {
		fmt.Fprintln(w, "<a href='"+root+"/login'>login</a>"+req.URL.Path)
	} else {
		fmt.Fprintln(w, "Hello,", user.Name)
	}
}

func UserHandler(w http.ResponseWriter, req *http.Request) {
	var userid int64
	if req.URL.Path == "/user/" {
		user, err := authenticate(req)
		if err != nil {
			http.Error(w, "User page error", http.StatusBadRequest)
			return
		}
		if user != nil {
			userid = user.Uid
		}
	} else {
		_, err := fmt.Sscanf(req.URL.Path, "/user/%d/", &userid)
		if err != nil {
			http.Error(w, "User page error", http.StatusBadRequest)
			log.Println("User page error, ", err)
			return
		}
	}

	var steamname string
	var stars string

	err := db.QueryRow("SELECT steamname, stars FROM users WHERE uid=?", userid).Scan(&steamname, &stars)
	if err == sql.ErrNoRows {
		http.Error(w, "No such user", http.StatusInternalServerError)
		return
	} else if err != nil {
		http.Error(w, "User page error", http.StatusInternalServerError)
		log.Println("Database error", err)
		return
	}

	attribs := make(map[string]interface{})
	attribs["userid"] = userid
	attribs["steamname"] = steamname
	attribs["stars"] = stars

	err = json.NewEncoder(w).Encode(attribs)
	if err != nil {
		http.Error(w, "User page error", http.StatusBadRequest)
		log.Println("User page error, ", err)
		return
	}
}

func LoginHandler(w http.ResponseWriter, req *http.Request) {
	url, err := openid.RedirectUrl("http://steamcommunity.com/openid",
		root+"/openidcallback", root)
	if err != nil {
		http.Error(w, "Error with openID redirect", http.StatusInternalServerError)
		log.Println("Error with openID redirect", err)
		return
	}
	http.Redirect(w, req, url, 303)
}

type SteamApiPlayer struct {
	Username string `json:"personaname"`
}

type SteamApiResponse struct {
	Response SteamApiPlayers `json:"response"`
}

type SteamApiPlayers struct {
	Players []SteamApiPlayer `json:"players"`
}

func AuthenticateHandler(w http.ResponseWriter, req *http.Request) {
	//Verify openID
	steamId, err := openid.Verify(
		root+req.URL.String(),
		discoveryCache, nonceStore)
	if err != nil {
		http.Error(w, "Login error", http.StatusInternalServerError)
		log.Println("Error with openID authentication", err)
		return
	}
	{
		const idPrefix = "http://steamcommunity.com/openid/id/"
		if steamId[0:len(idPrefix)] != idPrefix {
			http.Error(w, "Login error", http.StatusInternalServerError)
			log.Println("Not a steam openid", steamId)
			return
		}
		steamId = steamId[len(idPrefix):]
	}

	var user int64
	{
		err = db.QueryRow("SELECT uid FROM users WHERE steamid=?", steamId).Scan(&user)
		if err == sql.ErrNoRows {
			user = CreateUser(steamId)
			if user == 0 {
				http.Error(w, "Login error", http.StatusInternalServerError)
				return
			}
		} else if err != nil {
			http.Error(w, "Login error", http.StatusInternalServerError)
			log.Println("Database error", err)
			return
		}
	}

	var authtoken string
	{ //Use crypto rand to generate base32 token
		var buffer bytes.Buffer
		encoder := base32.NewEncoder(base32.StdEncoding, &buffer)
		_, err = io.CopyN(encoder, rand.Reader, 20)
		if err != nil {
			http.Error(w, "Login error", http.StatusInternalServerError)
			log.Println("Error generating auth token", err)
			return
		}
		err = encoder.Close()
		if err != nil {
			http.Error(w, "Login error", http.StatusInternalServerError)
			log.Println("Error generating auth token", err)
			return
		}
		authtoken = string(buffer.Bytes())
	}

	//Set authtoken in database
	_, err = db.Exec("UPDATE users SET authtoken=? WHERE uid=?", authtoken, user)
	if err != nil {
		http.Error(w, "Login error", http.StatusInternalServerError)
		log.Println("Database error", err)
		return
	}

	authtoken = strconv.FormatInt(user, 10) + "_" + authtoken

	//Set client's authtoken
	{
		expire := time.Now().AddDate(0, 0, 7) //Expire in 1 week
		cookie := http.Cookie{
			"authtoken", authtoken, "", rawroot, expire,
			expire.Format(time.UnixDate), 60 * 60 * 24 * 7, true, true,
			"authtoken=" + authtoken, []string{"authtoken=" + authtoken},
		}
		http.SetCookie(w, &cookie)

	}

	http.Redirect(w, req, root, 303)
}

func CreateUser(steamId string) (user int64) {
	var userName string
	{
		var apiResp SteamApiResponse
		resp, err := http.Get("http://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/?key=5FF09180C866D99FDAD4AB5401AF668F&steamids=" + steamId)
		if err != nil {
			log.Println("Unable to get steam name", err)
			return
		}
		decoder := json.NewDecoder(resp.Body)
		err = decoder.Decode(&apiResp)
		if err != nil {
			log.Println("Unable to get steam name", err)
			return
		}
		userName = apiResp.Response.Players[0].Username
		if userName == "" {
			log.Println("Unable to get steam name", err)
			return
		}
	}

	_, err := db.Exec("INSERT INTO users (steamid, steamname) VALUES (?,?)", steamId, userName)
	if err != nil {
		log.Println("Unable to create account", err)
		return
	}

	err = db.QueryRow("SELECT uid FROM users WHERE steamid=?", steamId).Scan(&user)
	if err != nil {
		log.Println("Database error", err)
		return 0
	}

	return
}

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
	http.HandleFunc("/user/", UserHandler)
	http.Handle(staticDir,
		http.StripPrefix(staticDir, http.FileServer(http.Dir("./static/"))))

	go MatchMaking()

	//Redirect http to https and serve https requests
	go func() {
		log.Fatal(http.ListenAndServe(":8080", http.HandlerFunc(
			func(w http.ResponseWriter, req *http.Request) {
				http.Redirect(w, req, root+req.RequestURI, http.StatusMovedPermanently)
			})))
	}()
	log.Fatal(http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil))

}

type User struct {
	Uid  int64
	Name string
}

func authenticate(req *http.Request) (*User, error) {
	authCookie, err := req.Cookie("authtoken")
	if err == http.ErrNoCookie {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	authToken := authCookie.Value
	underscorePos := 0
	for ; underscorePos < len(authToken); underscorePos++ {
		if authToken[underscorePos] == '_' {
			break
		}
	}

	var user User
	user.Uid, err = strconv.ParseInt(authToken[0:underscorePos], 10, 64)
	if err != nil {
		return nil, err
	}

	authToken = authToken[underscorePos+1:]
	var correctToken string
	err = db.QueryRow("SELECT authtoken, steamname FROM users WHERE uid=?", user.Uid).Scan(&correctToken, &user.Name)
	if err != nil {
		return nil, err
	}

	if authToken != correctToken {
		return nil, nil
	}

	return &user, nil
}

type MatchMakingChallenge struct {
	Challenger, Victum int64
}

var ListMatchMakingChan = make(chan chan []*User)
var EnterMatchMaking = make(chan *User)
var ExitMatchMaking = make(chan *User)
var PostMatchMakingChallenge = make(chan MatchMakingChallenge)

func MatchMaking() {
	currentChallengers := make([]*User, 0)
	for {
		select {
		case request := <-ListMatchMakingChan:
			requestResult := make([]*User, len(currentChallengers))
			copy(requestResult, currentChallengers)
			request <- requestResult

		case user := <-EnterMatchMaking:
			_ = user
		case user := <-ExitMatchMaking:
			_ = user
		case challenge := <-PostMatchMakingChallenge:
			_ = challenge
		}
	}
}
