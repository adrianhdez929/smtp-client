package main

import (
	"fmt"
	"smtpclient/client"
	"strings"
)

func handleError(err error) {
	if err != nil {
		fmt.Printf("error: %s\n", err)
		panic(err)
	}
}

func main() {
	var server string
	var domain string

	fmt.Println("Ingrese el servidor y dominio al que se quiere conectar.")
	fmt.Scanf("%s %s", &server, &domain)

	if server == "" || domain == "" {
		fmt.Println("El servidor y el dominio no pueden ser nulos.")
		return
	}

	c, err := client.NewSmptClient(server, domain, false)

	handleError(err)

	defer c.Close()

	err = c.Handshake(domain)

	handleError(err)

	var user string
	var password string
	var auth *client.SmtpAuth = nil

	fmt.Println("Ingrese su usuario. Deje en blanco para omitir la autenticacion.")
	fmt.Scanf("%s", &user)

	fmt.Println(user)

	if user != "" {
		fmt.Println("Ingrese su password.")
		fmt.Scanf("%s", &password)

		a := client.NewSmtpAuth(user, password)
		auth = &a
	}

	if auth != nil {
		err = c.Auth(*auth)
		handleError(err)
	}

	for {
		var command string
		fmt.Println("Ingrese la operacion que desea realizar.")
		fmt.Scanf("%s", &command)

		if strings.ToLower(command) == "quit" {
			err = c.Quit()
			handleError(err)
			break
		}

		switch strings.ToLower(command) {
		case "mail":
			var from string
			var to string
			var subject string
			var content string
			attatchments := make([]string, 0)

			fmt.Println("Inserte el remitente. Deje en blanco para usar su autenticacion.")
			fmt.Scanf("%s", &from)
			if from == "" {
				from = fmt.Sprintf("%s@%s", auth.Username(), domain)
			}
			fmt.Println("Inserte el destinatario.")
			fmt.Scanf("%s", &to)
			fmt.Println("Inserte el asunto.")
			fmt.Scanf("%s", &subject)
			fmt.Println("Inserte el contenido del mail.")
			fmt.Scanf("%s", &content)
			fmt.Println("Inserte los adjuntos. Deje en blanco para dejar de agregar.")
			for {
				var attatchment string
				fmt.Scanf("%s", &attatchment)

				if attatchment == "" {
					break
				}

				attatchments = append(attatchments, attatchment)
			}

			c.SendMail(to, from, subject, content, attatchments)
		case "noop":
			c.Noop()

		case "help":
			var section string
			fmt.Println("Inserte la seccion de la ayuda.")
			fmt.Scanf("%s", &section)
			c.Help(section)

		case "expand":
			var section string
			fmt.Println("Inserte el contenido a expandir.")
			fmt.Scanf("%s", &section)
			c.Expand(section)

		case "verify":
			var content string
			fmt.Println("Inserte el contenido a verificar.")
			fmt.Scanf("%s", &content)
			c.Verify(content)

		case "reset":
			c.Reset()

		default:
			continue
		}
	}

	// fmt.Println("hanshake successfull")

	// fmt.Println("send noop command")

	// err = client.Noop()

	// handleError(err)

	// err = client.SendMail("janedoe@example.org", "johndoe@example.com", "Hello World", "Hello Jane. This is my first email. Hope you are good. Good bye.")

	// handleError(err)

	// fmt.Println("email sent without error")

	err = c.Quit()

	handleError(err)

	fmt.Println("quit called successfully")
}
