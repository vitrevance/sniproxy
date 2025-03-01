package endpoints

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
)

type EndpointEntry struct {
	Domain  string
	Address string
	regex   *regexp.Regexp
}

// EndpointDB contains a set of endpoints
type EndpointDB struct {
	endpoints []EndpointEntry

	file string
}

// NewEndpointsDB gives an EndpointDB instance
func NewEndpointsDB(ctx context.Context, file string) *EndpointDB {
	db := &EndpointDB{
		endpoints: []EndpointEntry{},
		file:      file,
	}

	db.readFile()
	return db
}

func (e *EndpointDB) readFile() {
	// open endpoint file
	file, err := os.Open(e.file)
	if err != nil {
		log.Println("error updating endpoints", err)
		return
	}
	defer file.Close()

	// read all lines
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// split line
		line := scanner.Text()
		// split line
		ind := strings.LastIndex(line, ",")
		if ind == -1 {
			continue
		}
		parts := []string{line[:ind], line[ind+1:]}
		// add endpoint
		e.endpoints = append(e.endpoints, EndpointEntry{
			Domain:  parts[0],
			Address: parts[1],
			regex:   regexp.MustCompile(parts[0]),
		})
	}
}

func (e *EndpointDB) Get(endpoint string) (EndpointEntry, error) {
	for _, ep := range e.endpoints {
		if ep.regex.MatchString(endpoint) {
			return ep, nil
		}
	}
	return EndpointEntry{}, fmt.Errorf("failed to find entry for endpoint %v", endpoint)
}
