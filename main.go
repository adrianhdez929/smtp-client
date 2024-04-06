package main

import (
	"fmt"
	"smtpclient/client"
)

func handleError(err error) {
	if err != nil {
		fmt.Printf("error: %s\n", err)
		panic(err)
	}
}

func main() {
	auth := client.NewSmtpAuth("admin", "admin")
	client, err := client.NewSmptClient("localhost:25", "example.org", false)

	handleError(err)

	defer client.Close()

	err = client.Handshake("example.org")

	handleError(err)

	err = client.Auth(auth)

	handleError(err)

	fmt.Println("hanshake successfull")

	fmt.Println("send noop command")

	err = client.Noop()

	handleError(err)

	err = client.SendMail("janedoe@example.org", "johndoe@example.com", "Hello World", "Hello Jane. This is my first email. Hope you are good. Good bye.")

	handleError(err)

	fmt.Println("email sent without error")

	err = client.Quit()

	handleError(err)

	fmt.Println("quit called successfully")
}
