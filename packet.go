package main

type Packet interface {
	Dest() string
	Sender() string
	Info() string
}

