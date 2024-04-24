package client

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"fmt"
)

type SmtpAuth struct {
	username string
	password string
}

func NewSmtpAuth(username string, password string) SmtpAuth {
	return SmtpAuth{
		username,
		password,
	}
}

func (a SmtpAuth) Username() string {
	return a.username
}

func (a SmtpAuth) Plain() string {
	authString := "\x00" + a.username + "\x00" + a.password
	encodedAuth := base64.StdEncoding.EncodeToString([]byte(authString))

	return encodedAuth
}

func (a SmtpAuth) CramMd5(challenge string) (string, error) {
	decodedChallenge, err := base64.StdEncoding.DecodeString(challenge)

	if err != nil {
		return "", err
	}

	hash := hmac.New(md5.New, []byte(a.password))
	hash.Write(decodedChallenge)

	s := make([]byte, 0, hash.Size())

	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s %x", a.username, hash.Sum(s)))), nil
}
