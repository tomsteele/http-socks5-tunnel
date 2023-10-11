package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
}

func (c *Client) StartWorker() {
	for {
		job, err := c.getJob()
		// getJob() is going to error a lot.
		if err != nil {
			// Adjust as needed.
			time.Sleep(time.Duration(c.timeout) * time.Millisecond)
			continue
		}
		switch job.Command {
		case command.COMMAND_CONNECT:
			conn, err := net.Dial("tcp", job.Addr)
			if err != nil {
				fmt.Println("Error connecting to address:", err)
				continue
			}
			c.lock.Lock()
			c.sockets[job.SocketID] = conn
			c.lock.Unlock()

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

			buff := make([]byte, 4096)
			n, err := conn.Read(buff)
			if err != nil && err != io.EOF {
				fmt.Printf("error reading from socket: %s\n", err.Error())
				continue
			}
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
	resp, err := http.Get(c.apiURL)
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
	resp, err := http.Post(c.apiURL, "application/json", bytes.NewBuffer(data))
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

func main() {
	apiURL := flag.String("api", "http://127.0.0.1:1081/jobs", "api server URL")
	timeout := flag.Int("timeout", 500, "milliseconds to wait between polling for jobs")
	defaultHexKey := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	hexKey := flag.String("key", defaultHexKey, "AES-256 key as 64 hex characters.")
	flag.Parse()

	key, err := parseKey(*hexKey)
	if err != nil {
		fmt.Printf("error parsing key: %s\n", err.Error())
		os.Exit(1)
	}

	client := Client{
		apiURL:  *apiURL,
		sockets: make(map[int]net.Conn),
		key:     key,
		timeout: *timeout,
	}
	client.StartWorker()
}
