package main

import (
	"fmt"
	"net"
	"net/textproto"
)

type SmtpClient struct {
	conn       net.Conn
	proto      *textproto.Conn
	handshaked bool
}

func NewSmptClient(host string) (*SmtpClient, error) {
	sock, err := net.Dial("tcp", "localhost:25")

	if err != nil {
		return nil, err
	}

	textProto := textproto.NewConn(sock)
	_, _, err = textProto.ReadResponse(220)

	if err != nil {
		return nil, err
	}

	client := SmtpClient{
		sock,
		textProto,
		false,
	}

	return &client, nil
}

func (c *SmtpClient) Close() {
	c.conn.Close()
}

func (c *SmtpClient) Handshake() error {
	id, err := c.proto.Cmd("EHLO localhost")

	if err != nil {
		return err
	}

	c.proto.StartResponse(id)
	defer c.proto.EndResponse(id)
	_, _, err = c.proto.ReadResponse(250)

	if err != nil {
		return err
	}

	return nil
}

func (c *SmtpClient) Noop() error {
	id, err := c.proto.Cmd("NOOP")

	if err != nil {
		return err
	}

	c.proto.StartResponse(id)
	defer c.proto.EndResponse(id)
	_, msg, err := c.proto.ReadResponse(250)

	if err != nil {
		return err
	}

	fmt.Printf("Noop result: %s\n", msg)

	return nil
}

func handleError(err error) {
	if err != nil {
		fmt.Printf("error: %s\n", err)
		panic(err)
	}
}

func main() {
	client, err := NewSmptClient("localhost:25")

	handleError(err)

	defer client.Close()

	err = client.Handshake()

	handleError(err)

	fmt.Println("hanshake successfull")

	fmt.Println("send noop command")

	client.Noop()
}
