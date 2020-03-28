package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

var wg sync.WaitGroup
var helpString []byte

func init() {
	helpString, _ = ioutil.ReadFile("___help.~goapp")
}

func main() {
	ln, err := net.Listen("tcp", ":9090")
	if err != nil {
		return
	}
	for {
		conn, err := ln.Accept()
		wg.Add(1)
		if err != nil {
			conn.Close()
			wg.Done()
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	for {
		netData, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			fmt.Println(err)
			break
		}

		netData = strings.TrimSpace(netData)
		netData = strings.ReplaceAll(netData, " ", "")
		n := len(netData)
		if n >= 3 && netData[:3] == "get" && strings.Count(netData, `"`) == 2 {
			netData = netData[4:]
			filename, _ := getData(netData)
			if isLockFile(filename) || filename == "___help.~goapp" {
				conn.Write([]byte("Can't perform operation"))
			} else {
				conn.Write([]byte("ok" + getFile(filename)))
			}
		} else if n >= 5 && netData[:5] == "write" && strings.Count(netData, `"`) == 6 {
			netData = netData[6:]
			filename, pos := getData(netData)
			netData = netData[(pos + 1):]
			text, pos := getData(netData)
			netData = netData[(pos + 1):]
			password, _ := getData(netData)
			if isLockFile(filename) || filename == "___help.~goapp" || !canAccess(filename, password) {
				if !canAccess(filename, password) {
					conn.Write([]byte("Wrong Password"))
				} else {
					conn.Write([]byte("Private Data"))
				}
			} else {
				if !isLocked(filename) && password != "" {
					lock(filename, password)
				}
				write(filename, text)
				conn.Write([]byte("ok"))
			}
		} else if n >= 8 && netData[:8] == "islocked" && strings.Count(netData, `"`) == 2 {
			netData = netData[9:]
			filename, _ := getData(netData)
			if isLocked(filename) {
				conn.Write([]byte("yes"))
			} else {
				conn.Write([]byte("no"))
			}
		} else if n >= 10 && netData[:10] == "removelock" && strings.Count(netData, `"`) == 4 {
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
		} else if n >= 4 && netData[:4] == "help" {
			conn.Write(helpString)
		} else {
			conn.Write([]byte("Invalid command\n"))
		}
	}
	conn.Close()
	wg.Done()
}

func getData(str string) (string, int) {
	aux := ""
	n := len(str)
	i := 0
	for ; i < n && str[i] != '"'; i++ {
		aux += string([]byte{str[i]})
	}
	i++
	return aux, i
}

func exists(fileName string) bool {
	if _, err := os.Stat(fileName); err == nil {
		return true
	}
	return false
}

func getFile(fileName string) string {
	if !exists(fileName) {
		ioutil.WriteFile(fileName, []byte(""), 0666)
	}
	aux, _ := ioutil.ReadFile(fileName)
	return string(aux)
}

func isLocked(fileName string) bool {
	aux := "__" + fileName + ".~lock"
	return exists(aux)
}

func isLockFile(fileName string) bool {
	n := len(fileName)
	if n <= 8 {
		return false
	}
	return fileName[0:2] == "__" && fileName[n-6:n] == ".~lock"
}

func canAccess(fileName, password string) bool {
	if !isLocked(fileName) {
		return true
	}
	aux := "__" + fileName + ".~lock"
	hash, _ := ioutil.ReadFile(aux)
	return bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
}

func lock(fileName, password string) {
	aux, _ := bcrypt.GenerateFromPassword([]byte(password), 5)
	ioutil.WriteFile("__"+fileName+".~lock", aux, 0666)
}

func write(fileName, text string) {
	ioutil.WriteFile(fileName, []byte(text), 0666)
}

func removeLock(fileName string) {
	os.Remove("__" + fileName + ".~lock")
}
