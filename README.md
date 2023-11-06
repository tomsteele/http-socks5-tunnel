# http-socks5-tunnel
This implements a sock5 proxy over an HTTP API. I got the idea while perusing [Havoc's](https://github.com/HavocFramework/Havoc) code.

This might be useful, but it's probably not. It's more just a PoC for me (or you?) in future work.


## Usage
Going to assume you have `go` installed. You can use `--help` for more information. And you should, there are default AES keys in there and noisey timeout values.

**Build and start server**
```
$ cd cmd/server
$ go build
$ ./server
```

**Build client and start (somewhere)**
```
$ cd cmd/client
$ go build
$ ./client
```

**Probably review the usage for both**
```
Usage of client:
  -api string
    	api server URL (default "http://127.0.0.1:1081/jobs")
  -host string
    	Host header to be applied to every request
  -key string
    	AES-256 key as 64 hex characters. (default "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
  -timeout int
    	milliseconds to wait between polling for jobs (default 500)
  -ua string
    	user-agent to use (default "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36")
```


**Use the socks5 listener**
```
$ curl --verbose --proxy socks5://localhost:1080 -m 10 http://www.example.com/
```

## What doesn't work
Probably a lot. But for sure there is no support for TLS on the HTTP API. Can be added by using a reverse proxy in front of the API with a valid certificate. [Caddy](https://caddyserver.com/docs/quick-starts/reverse-proxy) is good for that. Otherwise it shoudn't be too much work for someone to modify the HTTP server and client to take invalid certs.
