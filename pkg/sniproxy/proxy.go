package sniproxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
		sni, pb, err := s.peekClientHello(conn)
		peekedBytes = pb
		if err != nil {

			if errors.Is(err, NotTLS) {
				domainName = "*"
			} else {
				return fmt.Errorf("error reading connection: %v", err)
			}
		} else {
			domainName = sni
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

type TLSHeader struct {
	Type    uint8
	Version uint16
}

type TLSRecord struct {
	Header TLSHeader
	Body   []byte
}

var ReadMore = errors.New("TLS size is greater than provided buffer")
var NotTLS = errors.New("not a TLS handshake")

func (s *SNIProxy) peekClientHello(reader io.Reader) (string, *bytes.Buffer, error) {
	peekedBytes := new(bytes.Buffer)

	var err error = ReadMore
	var tls TLSRecord
	inBuffer := make([]byte, 1024)
	for err != nil && errors.Is(err, ReadMore) {
		n, readErr := reader.Read(inBuffer)
		peekedBytes.Write(inBuffer[:n])
		if readErr != nil && (!errors.Is(readErr, io.EOF) || !errors.Is(err, ReadMore)) {
			return "", peekedBytes, fmt.Errorf("failed to read from connection: %w", readErr)
		}
		tls, err = parseTLSHandshake(peekedBytes.Bytes())
	}

	return tls.SNI(), peekedBytes, err
}

func parseTLSHandshake(buf []byte) (TLSRecord, error) {
	if buf[0] != 22 {
		return TLSRecord{}, NotTLS
	}
	version := binary.BigEndian.Uint16(buf[1:3])
	size := binary.BigEndian.Uint16(buf[3:5])
	if version != 0x0301 && version != 0x0302 && version != 0x0303 && version != 0x0304 {
		return TLSRecord{}, NotTLS
	}
	if int(size+5) > len(buf) {
		return TLSRecord{}, ReadMore
	}
	return TLSRecord{
		Header: TLSHeader{
			Type:    22,
			Version: version,
		},
		Body: buf[5 : size+5],
	}, nil
}

func (r *TLSRecord) SNI() string {
	pos := 1 + 3 + 2 + 32
	end := len(r.Body)

	if pos > end-1 {
		return ""
	}
	sessionIdSize := int(r.Body[pos])
	pos += 1 + sessionIdSize

	if pos > end-2 {
		return ""
	}
	cipherSuiteSize := int(binary.BigEndian.Uint16(r.Body[pos : pos+2]))
	pos += 2 + cipherSuiteSize

	if pos > end-1 {
		return ""
	}
	compressionTypeSize := int(r.Body[pos])
	pos += 1 + compressionTypeSize

	if pos > end-2 {
		return ""
	}
	extensionsSize := int(binary.BigEndian.Uint16(r.Body[pos : pos+2]))
	pos += 2

	if pos+extensionsSize > end {
		return ""
	}
	end = pos + extensionsSize

	for pos+4 < end {
		extType := binary.BigEndian.Uint16(r.Body[pos : pos+2])
		extSize := int(binary.BigEndian.Uint16(r.Body[pos+2 : pos+4]))
		pos += 4
		if extType == 0 {
			if pos > end-2 {
				return ""
			}
			namesLength := int(binary.BigEndian.Uint16(r.Body[pos : pos+2]))
			pos += 2

			// iterate over name list
			n := pos
			pos += namesLength
			if pos > end {
				return ""
			}
			for n < pos-3 {
				nameType := r.Body[n]
				nameSize := int(binary.BigEndian.Uint16(r.Body[n+1 : n+3]))
				n += 3

				if nameType == 0 {
					if n+nameSize > end {
						return ""
					}
					return string(r.Body[n : n+nameSize])
				}
			}
		} else {
			pos += extSize
		}
	}
	return ""
}
