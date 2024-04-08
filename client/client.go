package client

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strings"
)

type SmtpClient struct {
	conn       net.Conn
	proto      *textproto.Conn
	domain     string
	handshaked bool
	extensions map[string][]string
	tls        bool
	secure     bool
}

func NewSmptClient(host string, domain string, secure bool) (*SmtpClient, error) {
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
		domain,
		false,
		make(map[string][]string),
		false,
		secure,
	}

	return &client, nil
}

func (c *SmtpClient) Close() error {
	return c.conn.Close()
}

func (c *SmtpClient) loadExtensions(helloResponse string) {
	lines := strings.Split(helloResponse, "\r\n")

	for _, line := range lines {
		if strings.Contains(line, "=") {
			continue
		}

		lineSplit := strings.Split(line, " ")

		c.extensions[lineSplit[0]] = make([]string, 0)

		for i := 1; i < len(lineSplit)-1; i++ {
			ext := c.extensions[lineSplit[0]]
			_ = append(ext, lineSplit[i])
		}
	}
}

func (c *SmtpClient) requestMd5Challenge() (string, error) {
	id, err := c.proto.Cmd("AUTH CRAM-MD5")

	if err != nil {
		return "", err
	}

	c.proto.StartResponse(id)
	defer c.proto.EndResponse(id)

	_, msg, err := c.proto.ReadResponse(334)

	if err != nil {
		return "", err
	}

	return msg, nil
}

func (c *SmtpClient) Auth(auth SmtpAuth) error {
	command := ""

	if c.tls {
		// Secure connection, PLAIN auth
		command = fmt.Sprintf("AUTH PLAIN %s", auth.Plain())
	} else {
		// Insecure connection CRAM-MD5
		challenge, err := c.requestMd5Challenge()

		if err != nil {
			return err
		}

		solved, err := auth.CramMd5(challenge)

		if err != nil {
			return err
		}

		command = solved
	}

	id, err := c.proto.Cmd(command)

	if err != nil {
		return err
	}

	c.proto.StartResponse(id)
	defer c.proto.EndResponse(id)

	_, msg, err := c.proto.ReadResponse(235)

	if err != nil {
		return err
	}

	fmt.Printf("Auth result: %s\n", msg)

	return nil
}

func (c *SmtpClient) Handshake(domain string) error {
	if c.handshaked {
		return errors.New("already handshaked")
	}

	id, err := c.proto.Cmd(fmt.Sprintf("EHLO %s", c.domain))

	if err != nil {
		return err
	}

	c.proto.StartResponse(id)
	defer c.proto.EndResponse(id)
	_, msg, err := c.proto.ReadResponse(250)

	if err != nil {
		return err
	}

	c.handshaked = true

	c.loadExtensions(msg)

	if c.secure {
		err = c.secureConnection()

		if err != nil {
			return err
		}
	}

	return nil
}

func (c *SmtpClient) Reset() error {
	id, err := c.proto.Cmd("RSET")

	if err != nil {
		return err
	}

	c.proto.StartResponse(id)
	defer c.proto.EndResponse(id)
	_, _, err = c.proto.ReadResponse(250)

	if err != nil {
		return err
	}

	fmt.Println("reset was successfull")

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

func (c *SmtpClient) Verify(content string) error {
	id, err := c.proto.Cmd("VRFY %s", content)

	if err != nil {
		return err
	}

	c.proto.StartResponse(id)
	defer c.proto.EndResponse(id)
	_, msg, err := c.proto.ReadResponse(250)

	if err != nil {
		return err
	}

	fmt.Printf("Verify result: %s\n", msg)

	return nil
}

func (c *SmtpClient) Expand(content string) error {
	id, err := c.proto.Cmd("EXPN %s", content)

	if err != nil {
		return err
	}

	c.proto.StartResponse(id)
	defer c.proto.EndResponse(id)
	_, msg, err := c.proto.ReadResponse(250)

	if err != nil {
		return err
	}

	fmt.Printf("Expand result: %s\n", msg)

	return nil
}

func (c *SmtpClient) Help(content string) error {
	var id uint
	var err error

	if content == "" {
		id, err = c.proto.Cmd("HELP")
	} else {
		id, err = c.proto.Cmd("HELP %s", content)
	}

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

func (c *SmtpClient) Mail(from string) error {
	id, err := c.proto.Cmd(fmt.Sprintf("MAIL FROM:<%s>", from))

	if err != nil {
		return err
	}

	c.proto.StartResponse(id)
	defer c.proto.EndResponse(id)
	_, msg, err := c.proto.ReadResponse(250)

	if err != nil {
		return err
	}

	fmt.Printf("Mail result: %s\n", msg)

	return nil
}

func (c *SmtpClient) Recipient(to string) error {
	id, err := c.proto.Cmd(fmt.Sprintf("RCPT TO:<%s>", to))

	if err != nil {
		return err
	}

	c.proto.StartResponse(id)
	defer c.proto.EndResponse(id)
	_, msg, err := c.proto.ReadResponse(250)

	if err != nil {
		return err
	}

	fmt.Printf("Recipient result: %s\n", msg)

	return nil
}

func (c *SmtpClient) Data(content string) error {
	id, err := c.proto.Cmd("DATA")

	if err != nil {
		return err
	}

	c.proto.StartResponse(id)
	defer c.proto.EndResponse(id)
	_, _, err = c.proto.ReadResponse(354)

	if err != nil {
		return err
	}

	return nil
}

func (c *SmtpClient) StartTls() error {
	id, err := c.proto.Cmd("STARTTLS")

	if err != nil {
		return err
	}

	c.proto.StartResponse(id)
	defer c.proto.EndResponse(id)
	_, _, err = c.proto.ReadResponse(220)

	if err != nil {
		return err
	}

	return nil
}

func (c *SmtpClient) secureConnection() error {
	if !c.handshaked {
		return errors.New("you need to handshake first")
	}

	err := c.StartTls()

	if err != nil {
		return err
	}
	fmt.Println(c.conn.RemoteAddr().String())

	c.conn = tls.Client(c.conn, &tls.Config{ServerName: c.conn.RemoteAddr().String()})
	c.proto = textproto.NewConn(c.conn)
	c.tls = true

	fmt.Println("TLS started successfully")

	return nil
}

func (c *SmtpClient) Quit() error {
	id, err := c.proto.Cmd("QUIT")

	if err != nil {
		return err
	}

	c.proto.StartResponse(id)
	defer c.proto.EndResponse(id)
	_, msg, err := c.proto.ReadResponse(221)

	if err != nil {
		return err
	}

	fmt.Printf("Quit result: %s\n", msg)

	return c.conn.Close()
}

func (c *SmtpClient) sendHeaders(to string, from string, subject string) error {
	err := c.proto.Writer.PrintfLine(fmt.Sprintf("From:%s", from))

	if err != nil {
		return err
	}

	err = c.proto.Writer.PrintfLine(fmt.Sprintf("To:%s", to))

	if err != nil {
		return err
	}

	err = c.proto.Writer.PrintfLine(fmt.Sprintf("Subject:%s", subject))

	if err != nil {
		return err
	}

	err = c.proto.Writer.PrintfLine("")

	if err != nil {
		return err
	}

	return nil
}

func (c *SmtpClient) SendMail(to string, from string, subject string, content string) error {
	err := c.Mail(to)

	if err != nil {
		return err
	}

	err = c.Recipient(to)

	if err != nil {
		return err
	}

	err = c.Data(content)

	if err != nil {
		return err
	}

	err = c.sendHeaders(to, from, subject)

	if err != nil {
		return err
	}

	contentLines := strings.Split(content, ".")

	for idx, line := range contentLines {
		if idx == len(contentLines)-1 {
			err = c.proto.Writer.PrintfLine(line)
		} else {
			err = c.proto.Writer.PrintfLine(fmt.Sprintf("%s.", line))
		}

		if err != nil {
			return err
		}
	}

	id, err := c.proto.Cmd("\r\n.")

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
