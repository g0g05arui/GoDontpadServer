package main

import (
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"text/template"

	"golang.org/x/crypto/bcrypt"
)

var wg sync.WaitGroup
var helpString []byte
var officialPassword []byte
var pageCode, indexCode []byte
var lastLogIndex int
var logFile *os.File
var charWrittenInLogFile int

/*
	pageCode template helper struct
*/
type Helper struct {
	Title   string
	Content string
}

func init() {
	helpString, _ = ioutil.ReadFile("__help.~goapp")
	officialPassword, _ = ioutil.ReadFile("__password.~goapp")
	pageCode, _ = ioutil.ReadFile("file.html")
	indexCode, _ = ioutil.ReadFile("index.html")
}

/*
*@desc listens to port 9090 and launches client threads
 */
func main() {
	server8000 := http.NewServeMux()
	ln, err := net.Listen("tcp", ":9090")
	server8000.HandleFunc("/", mainHandler)
	server8000.HandleFunc("/view/", viewHandler)
	server8000.HandleFunc("/save", saveHandler)
	server8000.HandleFunc("/lock", lockHandler)
	server8000.HandleFunc("/unlock", unlockHandler)
	server8000.HandleFunc("/refresh", refreshHandler)
	server8000.HandleFunc("/md5", md5Handler)
	server8433 := http.NewServeMux()
	server8433.HandleFunc("/", mainHandler)
	server8433.HandleFunc("/view/", viewHandler)
	server8433.HandleFunc("/save", saveHandler)
	server8433.HandleFunc("/lock", lockHandler)
	server8433.HandleFunc("/unlock", unlockHandler)
	server8433.HandleFunc("/refresh", refreshHandler)
	server8433.HandleFunc("/md5", md5Handler)
	wg.Add(1)
	go func() {
		http.ListenAndServeTLS(":8000", "server.cert", "server.key", server8000)
		wg.Done()
	}()
	wg.Add(1)
	go func() {
		http.ListenAndServe(":8433", server8433)
		wg.Done()
	}()
	if err != nil {
		return
	}
	for {
		conn, err := ln.Accept()
		fmt.Println("Connected")
		wg.Add(1)
		if err != nil {
			conn.Close()
			wg.Done()
			continue
		}
		go handleConnection(conn)
	}
}

/*
* @desc handles connections
* parses commands and executes them then responds to the client
 */

func handleConnection(conn net.Conn) {
	buf := make([]byte, 1024*1024)
	req, _ := conn.Read(buf)
	netData := string(buf[:req])
	logString(conn.RemoteAddr().String() + " " + netData)
	if validateConnection(netData) == false {
		logString("Invalid password:" + netData)
		conn.Write([]byte("Invalid password"))
		conn.Close()
		return
	}
	conn.Write([]byte("ok password"))
	for {
		req, err := conn.Read(buf)
		netData = string(buf[:req])

		if err != nil {
			fmt.Println(err)
			break
		}
		//Parse input
		netData = strings.TrimSpace(netData)
		logString(conn.RemoteAddr().String() + " " + netData)
		n := len(netData)
		//Validates and executes commands
		netData = strings.ReplaceAll(netData, `[[\n]]`, "\n")
		if n >= 3 && netData[:3] == "get" && strings.Count(netData, `"`) == 2 { // Sends client the content of a file
			netData = netData[4:]
			filename, _ := getData(netData)
			if isLockFile(filename) || filename == "file.html" || filename == "index.htmml" || filename == "___help.~goapp" || filename == "__password.~goapp" || filename == "main.go" { //Checks if a file is private
				conn.Write([]byte("Can't perform operation"))
			} else {
				conn.Write([]byte("ok " + getFile(filename)))
			}

		} else if n >= 5 && netData[:5] == "write" && strings.Count(netData, `"`) >= 6 { //Writes to an existing file or creates a new file with a password if told
			netData = netData[6:]
			filename, pos := getData(netData)
			netData = netData[(pos + 1):]
			password, pos := getData(netData)
			netData = netData[(pos + 1):]
			text := netData[1 : len(netData)-1]
			if isLockFile(filename) || filename == "index.html" || filename == "file.html" || filename == "___help.~goapp" || filename == "__password.~goapp" || filename == "main.go" || !canAccess(filename, password) { //Checks for password of for protected files
				if !canAccess(filename, password) {
					conn.Write([]byte("Wrong Password"))
				} else {
					conn.Write([]byte("Private Data"))
				}
			} else {
				write(filename, text)
				conn.Write([]byte("ok"))
			}

		} else if n >= 8 && netData[:8] == "islocked" && strings.Count(netData, `"`) == 2 { //Checks if a file is password-protected

			netData = netData[9:]
			filename, _ := getData(netData)
			if isLocked(filename) {
				conn.Write([]byte("yes"))
			} else {
				conn.Write([]byte("no"))
			}

		} else if n >= 10 && netData[:10] == "removelock" && strings.Count(netData, `"`) == 4 { //Removes the password of a file if the password is correct

			netData = netData[11:]
			filename, pos := getData(netData)
			netData = netData[(pos + 1):]
			password, _ := getData(netData)

			if isLocked(filename) {
				if canAccess(filename, password) {
					removeLock(filename)
					conn.Write([]byte("removed"))
				} else {
					conn.Write([]byte("wrong password"))
				}
			} else {
				conn.Write([]byte("Ok"))
			}
		} else if n >= 4 && netData[:4] == "lock" && strings.Count(netData, `"`) >= 4 {
			netData = netData[5:]
			filename, pos := getData(netData)
			netData = netData[(pos + 1):]
			password, _ := getData(netData)
			if isLocked(filename) {
				conn.Write([]byte("already locked"))
			} else {
				lock(filename, password)
				conn.Write([]byte("ok"))
			}
		} else if n >= 4 && netData[:4] == "help" {
			conn.Write(helpString)
		} else {
			conn.Write([]byte("Invalid command\n"))
		}
	}
	conn.Close()
	wg.Done()
}

/*
* @ desc gets a string between two " characters
* returns the string and the position of the next " character or the end
* string must start with anything else than a "
 */

func restOf(str string) string {
	return ""
}

func getData(str string) (string, int) {
	aux := ""
	n := len(str)
	i := 0
	for ; str[i] != '"'; i++ {

	}
	i++
	for ; i < n && str[i] != '"'; i++ {
		aux += string([]byte{str[i]})
	}
	i++
	return aux, i
}

/*
* @ checks if a file exists
 */

func exists(fileName string) bool {
	if _, err := os.Stat(fileName); err == nil {
		return true
	}
	return false
}

/*
* @ returns the content of a file
 */

func getFile(fileName string) string {
	fileName = "files/" + fileName
	if !exists(fileName) {
		ioutil.WriteFile(fileName, []byte(""), 0666)
	}
	aux, _ := ioutil.ReadFile(fileName)
	return string(aux)
}

/*
* @ checks if a file is password protected
* default format for a lock file is __filename.~lock
 */

func isLocked(fileName string) bool {
	aux := "lock/__" + fileName + ".~lock"
	return exists(aux)
}

/*
* @ checks if the filename is a file used for password protection
 */
func isLockFile(fileName string) bool {
	n := len(fileName)
	if n <= 8 {
		return false
	}
	return fileName[0:2] == "__" && fileName[n-6:n] == ".~lock"
}

/*
* @ checks if a file can be accessed using a password(if protected)
 */
func canAccess(fileName, password string) bool {
	if !isLocked(fileName) {
		return true
	}
	aux := "lock/__" + fileName + ".~lock"
	hash, _ := ioutil.ReadFile(aux)
	return bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
}

/*
* @ creates a lock file with a specified password
* @ uses the deafult format for lock files
 */

func lock(fileName, password string) {
	aux, _ := bcrypt.GenerateFromPassword([]byte(password), 5)
	ioutil.WriteFile("lock/__"+fileName+".~lock", aux, 0666)
}

/*
* @ updates or crates a file with specified text
 */

func write(fileName, text string) {
	ioutil.WriteFile("files/"+fileName, []byte(text), 0666)
}

/*
*@ removes the lock file for the spcified filename
 */

func removeLock(fileName string) {
	os.Remove("lock/__" + fileName + ".~lock")
}

func validateConnection(password string) bool {
	return bcrypt.CompareHashAndPassword(officialPassword, []byte(password)) == nil
}

/*
	@ReadUserIp(r)
	returns the ip of a user as string
	from a http Request
*/

func ReadUserIP(r *http.Request) string {
	IPAddress := r.Header.Get("X-Real-Ip")
	if IPAddress == "" {
		IPAddress = r.Header.Get("X-Forwarded-For")
	}
	if IPAddress == "" {
		IPAddress = r.RemoteAddr
	}
	return IPAddress
}

/*
	@mainHandler (w,r)
	@desc respondes to the main page event
	and logs user's IP
*/

func mainHandler(w http.ResponseWriter, r *http.Request) {
	logString(ReadUserIP(r) + " on main " + r.RequestURI)
	fmt.Fprintf(w, "%s", string(indexCode))
}

/*
	@viewHandler(w,r)
	@desc respondes to the view page request
	sending the html file with the file's content
*/

func viewHandler(w http.ResponseWriter, r *http.Request) {
	logString(ReadUserIP(r) + " on view " + r.RequestURI)
	tmpl, _ := template.New("html").Parse(string(pageCode))
	filename := r.RequestURI[6:]
	if !isLockFile(filename) && filename != "index.html" && filename != "file.html" && filename != "__help.~goapp" && filename != "__password.~goapp" && filename != "main.go" {
		tmpl.Execute(w, Helper{filename, getFile(filename)})
	} else {
		fmt.Fprintf(w, "Can't access page")
	}
}

/*
	@saveHandler(w,r)
	@desc : handles save for a file's
	request
*/

func saveHandler(w http.ResponseWriter, r *http.Request) {
	logString(ReadUserIP(r) + " on save " + r.RequestURI)
	r.ParseForm()
	if canAccess(r.FormValue("f"), r.FormValue("p")) {
		write(r.FormValue("f"), r.FormValue("textx"))
		fmt.Fprintf(w, "ok")
	} else {
		fmt.Fprintf(w, "no")
	}
}

/*
	@lockHandler(w,r)
	@desc : if a file isn't already locked
	it locks it with the specified password
	and returns the apropiate response
*/

func lockHandler(w http.ResponseWriter, r *http.Request) {
	logString(ReadUserIP(r) + " on lock " + r.RequestURI)
	filename := r.URL.Query().Get("f")
	password := r.URL.Query().Get("p")
	if !isLocked(filename) && !isLockFile(filename) && filename != "index.html" && filename != "file.html" && filename != "__help.~goapp" && filename != "__password.~goapp" && filename != "main.go" {
		lock(filename, password)
		fmt.Fprintf(w, "File locked successfully")
	} else {
		fmt.Fprintf(w, "File is already locked")
	}
}

/*
	@unlockHandler(w,r)
	@desc handles the unlock request if
	the file is locked with the specified
	password and returns the status
*/

func unlockHandler(w http.ResponseWriter, r *http.Request) {
	logString(ReadUserIP(r) + " on unlock " + r.RequestURI)
	filename := r.URL.Query().Get("f")
	password := r.URL.Query().Get("p")
	if canAccess(filename, password) {
		removeLock(filename)
		fmt.Fprintf(w, "File has been unlocked")
	} else {
		fmt.Fprintf(w, "Wrong Passowrd")
	}
}

/*
	@refreshHandler(w,r)
	@desc handles the refresh querry
	returns the page content with the file
*/

func refreshHandler(w http.ResponseWriter, r *http.Request) {
	logString(ReadUserIP(r) + " on refresh " + r.RequestURI)
	filename := r.URL.Query().Get("f")
	fmt.Fprintf(w, "%s", getFile(filename))
}

func md5Handler(w http.ResponseWriter, r *http.Request) {
	logString(ReadUserIP(r) + "on md5 " + r.RequestURI)
	filename := r.URL.Query().Get("f")
	fmt.Fprintf(w, "%x", md5.Sum([]byte(getFile(filename))))
}

func logString(log string) {
	if lastLogIndex == 0 {
		logFile, _ = os.OpenFile("logs/log1.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		lastLogIndex++
	} else if charWrittenInLogFile >= 1024*1024*4 {
		logFile.Close()
		lastLogIndex++
		logFile, _ = os.OpenFile("logs/log"+strconv.Itoa(lastLogIndex)+".txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	fmt.Fprintln(logFile, log)
	charWrittenInLogFile += len(log)
}
