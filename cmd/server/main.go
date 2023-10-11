package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/tomsteele/http-socks5-tunnel/pkg/command"
	"github.com/tomsteele/http-socks5-tunnel/pkg/crypt"

	"github.com/gin-gonic/gin"
)

func randomInt() int {
	return int(rand.Uint32())
}

type Connection struct {
	conn net.Conn
	addr string
}

type SocksL struct {
	db    map[int]Connection
	queue chan command.Job
	lock  sync.Mutex
	key   []byte
}

func (s *SocksL) handleConnection(conn net.Conn) error {
	defer conn.Close()

	buffer := make([]byte, 2)
	_, err := io.ReadFull(conn, buffer)
	if err != nil {
		return err
	}
	// First validate the socks version.
	if buffer[0] != 0x05 {
		return fmt.Errorf("invalid SOCKS version")
	}

	// Next read in the number of auth methods. It's important we read these all in.
	nauth := buffer[1]
	authMethods := make([]byte, nauth)
	_, err = io.ReadFull(conn, authMethods)
	if err != nil {
		return err
	}

	// Make sure the client supports 0x00 authentication.
	if !bytes.Contains(authMethods, []byte{0x00}) {
		return fmt.Errorf("no acceptable authentication methods")
	}

	// Tell the client we're ready for a command.
	conn.Write([]byte{0x05, 0x00})

	buffer = make([]byte, 4)
	_, err = io.ReadFull(conn, buffer)
	if err != nil {
		return err
	}
	cmd := buffer[1]
	atyp := buffer[3]

	// We only support CONNECT.
	if cmd != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00})
		return nil
	}

	var addr string
	// Turn the atyp into a string that we can dial.
	switch atyp {
	case 0x01:
		ipv4 := make([]byte, 4)
		port := make([]byte, 2)
		_, err = io.ReadFull(conn, ipv4)
		_, err = io.ReadFull(conn, port)
		addr = fmt.Sprintf("%d.%d.%d.%d:%d", ipv4[0], ipv4[1], ipv4[2], ipv4[3], binary.BigEndian.Uint16(port))
	case 0x03:
		length := make([]byte, 1)
		_, err = io.ReadFull(conn, length)
		domain := make([]byte, length[0])
		port := make([]byte, 2)
		_, err = io.ReadFull(conn, domain)
		_, err = io.ReadFull(conn, port)
		addr = fmt.Sprintf("%s:%d", domain, binary.BigEndian.Uint16(port))
	case 0x04:
		ipv6 := make([]byte, 16)
		port := make([]byte, 2)
		_, err = io.ReadFull(conn, ipv6)
		_, err = io.ReadFull(conn, port)
		addr = fmt.Sprintf("[%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x]:%d", ipv6[0], ipv6[1], ipv6[2], ipv6[3], ipv6[4], ipv6[5], ipv6[6], ipv6[7], ipv6[8], ipv6[9], ipv6[10], ipv6[11], ipv6[12], ipv6[13], ipv6[14], ipv6[15], binary.BigEndian.Uint16(port))
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00})
		return nil
	}

	// Create a random ID for our "db" and store the socket so we can write to it when the HTTP client reads.
	r := randomInt()
	s.lock.Lock()
	s.db[r] = Connection{conn: conn, addr: addr}
	s.lock.Unlock()
	// Queue a job to create a connection
	job := command.Job{
		Command:  command.COMMAND_CONNECT,
		SocketID: r,
		Addr:     addr,
	}
	s.queue <- job
	// Just assume we can connect for now.
	// This is some socks magic that doesn't seem to matter.
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	s.listenForData(r, conn)
	return nil
}

func (s *SocksL) listenForData(socketID int, conn net.Conn) {
	buffer := make([]byte, 1024)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				fmt.Printf("read error on socket %s\n", err.Error())
			}
			conn.Close()
			delete(s.db, socketID)
			break
		}
		job := command.Job{
			Command:  command.COMMAND_TX,
			SocketID: socketID,
			Data:     buffer[:n],
		}
		s.queue <- job
	}
}

func (s *SocksL) jobs(c *gin.Context) {
	switch c.Request.Method {
	case http.MethodPost:
		// Handle POST request: add Job to the queue.
		var jobWrap command.JobWrap
		if err := c.ShouldBindJSON(&jobWrap); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var job command.Job
		if err := crypt.Decrypt(s.key, jobWrap.Data, &job); err != nil {
			// TODO: Probably shouldn't leak information about decryption errors.
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// Additional handling for COMMAND_RX
		if job.Command == command.COMMAND_RX {
			// Retrieve the connection based on the SocketID
			conn, ok := s.db[job.SocketID]
			if !ok {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid socket_id"})
				return
			}
			// Write data to the socket
			_, err := conn.conn.Write(job.Data)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to write data to socket"})
				return
			}
		}
		// Add the job to the queue for other types of commands as well.
		s.queue <- job
		c.JSON(http.StatusOK, gin.H{"status": "ok"})

	case http.MethodGet:
		// Handle GET request: retrieve Job from the queue.
		select {
		case job := <-s.queue:
			ciphertext, err := crypt.Encrypt(s.key, job)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get data"})
				return
			}
			jobWrap := command.JobWrap{Data: ciphertext}
			c.JSON(http.StatusOK, jobWrap)
		default:
			c.JSON(http.StatusNoContent, gin.H{"status": "no jobs available"})
		}
	default:
		// Handle unexpected HTTP methods.
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "method not allowed"})
	}
}

func parseKey(hexKey string) ([]byte, error) {
	if len(hexKey) != 64 {
		return nil, fmt.Errorf("key must be 64 hexadecimal characters (32 bytes) for AES-256")
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex key: %v", err)
	}
	return key, nil
}

func main() {
	socksAddr := flag.String("socks", "127.0.0.1:1080", "socks5 server address")
	apiAddr := flag.String("api", "127.0.0.1:1081", "api server address")
	defaultHexKey := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	hexKey := flag.String("key", defaultHexKey, "AES-256 key as 64 hex characters.")
	flag.Parse()

	key, err := parseKey(*hexKey)
	if err != nil {
		fmt.Printf("error parsing key: %s\n", err.Error())
		os.Exit(1)
	}

	listener, err := net.Listen("tcp", *socksAddr)
	if err != nil {
		fmt.Printf("error starting socks server: %s\n", err.Error())
		os.Exit(1)
	}
	fmt.Printf("socks server started on %s\n", *socksAddr)

	s := SocksL{db: make(map[int]Connection), queue: make(chan command.Job, 100), key: key}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				fmt.Printf("error accepting new connection on socks server: %s\n", err.Error())
				return
			}
			go s.handleConnection(conn)
		}
	}()

	fmt.Printf("api started on %s\n", *apiAddr)
	r := gin.New()
	r.Use(gin.Recovery())
	// Leave this for testing.
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	r.Any("/jobs", s.jobs)
	r.Run(*apiAddr)
}
