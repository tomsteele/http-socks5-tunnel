package command

const COMMAND_CONNECT = 1
const COMMAND_TX = 2
const COMMAND_RX = 3

type JobWrap struct {
	Data string `json:"data"`
}

type Job struct {
	Command  int    `json:"command"`
	SocketID int    `json:"socket_id"`
	Addr     string `json:"addr"`
	Data     []byte `json:"data"`
}
