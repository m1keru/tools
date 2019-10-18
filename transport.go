package tools

import (
	"errors"
	"github.com/rs/xid"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"strings"
	"time"
)

// SSHConfig - структура содержащая настройка подключения по ssh
type SSHConfig struct {
	Host, Port, Login, Password, Keypath string
}

// RunOverSSH - выполняет указанную команду на указанном в SSHConfig хосте
func RunOverSSH(config *SSHConfig, command string) ([]byte, error) {
	sshConfig := &ssh.ClientConfig{
		User:            config.Login,
		Auth:            []ssh.AuthMethod{publicKeyFile(config.Keypath)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second}
	client, err := ssh.Dial("tcp", config.Host+":"+config.Port, sshConfig)
	if err != nil {
		return nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := client.Close(); err != nil {
			panic("Cannot Close client")
		}
	}()

	out, err := session.CombinedOutput(command)
	if err != nil {
		log.Println(string(out))
		return nil, err
	}
	return out, nil
}

func publicKeyFile(file string) ssh.AuthMethod {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		log.Println("cannot open RSA keyfile:", err)
		return nil
	}
	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		log.Println("cannot parse RSA private key")
		return nil
	}
	return ssh.PublicKeys(key)
}

var ChanStack = map[string]chan []byte{}

func RunOverSshChan(config *SSHConfig, command string) (string, error) {
	sshConfig := &ssh.ClientConfig{
		User:            config.Login,
		Auth:            []ssh.AuthMethod{publicKeyFile(config.Keypath)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second}
	client, err := ssh.Dial("tcp", config.Host+":"+config.Port, sshConfig)
	if err != nil {
		return "", err
	}

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}

	reader, err := session.StdoutPipe()
	if err != nil {
		return "", err
	}

	go session.Run(command)

	chanId := xid.New().String()
	ChanStack[chanId] = make(chan []byte)

	go chanReader(ChanStack[chanId], reader, chanId)

	return chanId, nil
}

func chanReader(ior chan []byte, reader io.Reader, chanId string) {
	b := make([]byte, 128)
	for {
		_, err := reader.Read(b)
		if err == io.EOF {
			ior <- []byte("done")
			delete(ChanStack, chanId)
			close(ior)
			b = nil
			break
		}
		ior <- b
	}
}
