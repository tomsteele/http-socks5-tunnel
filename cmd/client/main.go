package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/tomsteele/http-socks5-tunnel/pkg/command"
	"github.com/tomsteele/http-socks5-tunnel/pkg/crypt"
)

type Client struct {
	sockets map[int]net.Conn
	lock    sync.Mutex
	apiURL  string
	key     []byte
	timeout int
	httpc   *http.Client
}

func (c *Client) StartWorker() {
	modifiedTimeout := c.timeout
	stepTimeout := 500
	maxTimeout := 15000
	for {
		job, err := c.getJob()
		// This is going to error a lot and is safe to ignore. You may have to fiddle with timeouts.
		if err != nil {
			// Adjust as needed.
			jitter := rand.Intn(300)
			time.Sleep(time.Duration(modifiedTimeout+jitter) * time.Millisecond)
			if modifiedTimeout < maxTimeout {
				modifiedTimeout += stepTimeout
			}
			continue
		}
		modifiedTimeout = c.timeout
		switch job.Command {
		// Connect to the address and create a new socket.
		case command.COMMAND_CONNECT:
			conn, err := net.Dial("tcp", job.Addr)
			if err != nil {
				fmt.Println("Error connecting to address:", err)
				continue
			}
			// Locking here incase we want to increase the amount of workers in the future.
			c.lock.Lock()
			c.sockets[job.SocketID] = conn
			c.lock.Unlock()
			// Now that we have a connection it is ok to start processing the reads in another grooutine.
			go c.rx(conn, job)

		case command.COMMAND_TX:
			conn, ok := c.sockets[job.SocketID]
			if !ok {
				fmt.Printf("invalid socket id for COMMAND_TX. socket_id: %d\n", job.SocketID)
				continue
			}
			_, err = conn.Write(job.Data)
			if err != nil {
				fmt.Printf("error writing to socket: %s\n", err.Error())
				continue
			}
		// This is important. Applications needs to know when the socket is closed.
		case command.COMMAND_CLOSE:
			conn, ok := c.sockets[job.SocketID]
			if !ok {
				fmt.Printf("invalid socket id for COMMAND_CLOSE. socket_id: %d\n", job.SocketID)
				continue
			}
			conn.Close()
			c.lock.Lock()
			delete(c.sockets, job.SocketID)
			c.lock.Unlock()
		}
	}
}

func (c *Client) rx(conn net.Conn, job command.Job) {
	for {
		buff := make([]byte, 4096)
		n, err := conn.Read(buff)
		if err != nil {
			rxJob := command.Job{
				Command:  command.COMMAND_CLOSE,
				SocketID: job.SocketID,
				Data:     []byte{},
			}
			c.sendJob(rxJob)
			break
		}
		if n > 0 {
			rxJob := command.Job{
				Command:  command.COMMAND_RX,
				SocketID: job.SocketID,
				Data:     buff[:n],
			}
			if err := c.sendJob(rxJob); err != nil {
				fmt.Printf("error sending job: %s", err.Error())
			}
		}
	}
}

func (c *Client) getJob() (command.Job, error) {
	resp, err := c.httpc.Get(c.apiURL)
	if err != nil {
		return command.Job{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return command.Job{}, fmt.Errorf("http status not OK: %s", resp.Status)
	}
	var jobWrap command.JobWrap
	if err := json.NewDecoder(resp.Body).Decode(&jobWrap); err != nil {
		return command.Job{}, err
	}
	var job command.Job
	if err := crypt.Decrypt(c.key, jobWrap.Data, &job); err != nil {
		fmt.Printf("error during decyryption: %s\n", err.Error())
		return job, err
	}
	return job, nil
}

func (c *Client) sendJob(job command.Job) error {
	ciphertext, err := crypt.Encrypt(c.key, job)
	if err != nil {
		return err
	}
	jobWrap := command.JobWrap{Data: ciphertext}
	data, err := json.Marshal(jobWrap)
	if err != nil {
		return err
	}
	resp, err := c.httpc.Post(c.apiURL, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http status not OK: %s", resp.Status)
	}
	return nil
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

type customRoundTripper struct {
	HostHeader string
	UserAgent  string
	Transport  http.RoundTripper
}

func (t *customRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", t.UserAgent)
	if t.HostHeader != "" {
		req.Host = t.HostHeader
	}
	return t.Transport.RoundTrip(req)
}

func main() {
	apiURL := flag.String("api", "http://127.0.0.1:1081/jobs", "api server URL")
	hostHeader := flag.String("host", "", "Host header to be applied to every request")
	userAgent := flag.String("ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36", "user-agent to use")
	timeout := flag.Int("timeout", 500, "milliseconds to wait between polling for jobs")
	defaultHexKey := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	hexKey := flag.String("key", defaultHexKey, "AES-256 key as 64 hex characters.")
	flag.Parse()

	key, err := parseKey(*hexKey)
	if err != nil {
		fmt.Printf("error parsing key: %s\n", err.Error())
		os.Exit(1)
	}

	transport := customRoundTripper{
		UserAgent:  *userAgent,
		HostHeader: *hostHeader,
		Transport:  http.DefaultTransport,
	}

	httpc := http.Client{
		Transport: &transport,
	}

	client := Client{
		apiURL:  *apiURL,
		sockets: make(map[int]net.Conn),
		key:     key,
		timeout: *timeout,
		httpc:   &httpc,
	}
	client.StartWorker()
}
