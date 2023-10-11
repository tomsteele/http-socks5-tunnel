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


**Use the socks5 listener**
```
$ curl --verbose --proxy socks5://localhost:1080 -m 10 http://www.example.com/
```

## What doesn't work
Probably a lot. But for sure there is no support for TLS on the HTTP API. Can be added by using a reverse proxy in front of the API with a valid certificate. [Caddy](https://caddyserver.com/docs/quick-starts/reverse-proxy) is good for that. Otherwise it shoudn't be too much work for someone to modify the HTTP server and client to take invalid certs.