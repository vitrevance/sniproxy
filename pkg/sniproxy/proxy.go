package sniproxy

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/vitrevance/sniproxy/pkg/endpoints"
)

// SNIProxy is an SNI aware non-decrypting SNI proxy module
type SNIProxy struct {
	endpointsDB *endpoints.EndpointDB
}

// NewSNIProxy gives an new SNIProxy instance
func NewSNIProxy(endpointsDB *endpoints.EndpointDB) *SNIProxy {
	return &SNIProxy{
		endpointsDB: endpointsDB,
	}
}

func (s *SNIProxy) HandleConnection(conn net.Conn) error {
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
		return fmt.Errorf("error setting read timeout: %w", err)
	}

	domainName := ""
	var peekedBytes *bytes.Buffer
	{
		clientHello, pb, err := s.peekClientHello(conn)
		peekedBytes = pb
		if err != nil {
			domainName = "*"
			log.Printf("error reading SNI: %v", err)
		} else {
			domainName = clientHello.ServerName
		}
	}
	clientReader := io.MultiReader(peekedBytes, conn)

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return fmt.Errorf("error removing timeout: %w", err)
	}

	ep, err := s.endpointsDB.Get(domainName)
	if err != nil {
		return fmt.Errorf("error routing domain %s: %w", domainName, err)
	}

	backendConn, err := net.Dial("tcp", fmt.Sprintf("%s", ep.Address))
	if err != nil {
		return fmt.Errorf("error dialing backend: %w", err)
	}
	defer backendConn.Close()

	// we make a wait group to wait for the 2-way copy to finish
	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		io.Copy(conn, backendConn)
		conn.(*net.TCPConn).Close()
		wg.Done()
	}()
	go func() {
		io.Copy(backendConn, clientReader)
		backendConn.Close()
		wg.Done()
	}()

	wg.Wait()

	return nil
}

func (s *SNIProxy) peekClientHello(reader io.Reader) (*tls.ClientHelloInfo, *bytes.Buffer, error) {
	peekedBytes := new(bytes.Buffer)

	var hello *tls.ClientHelloInfo

	err := tls.Server(writeMockingConn{reader: io.TeeReader(reader, peekedBytes)}, &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = new(tls.ClientHelloInfo)
			*hello = *argHello
			return nil, nil
		},
	}).Handshake()

	// the error here is expected as we will not complete the handshake we just need the hello
	if hello == nil {
		return nil, nil, err
	}

	return hello, peekedBytes, nil
}
