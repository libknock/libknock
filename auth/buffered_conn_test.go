package auth

import (
	"bufio"
	"io"
	"net"
	"testing"
)

func TestBufferedConnReturnsBufferedBytesBeforeConnRead(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()
	writeErr := make(chan error, 1)
	go func() { _, err := client.Write([]byte("abc")); writeErr <- err }()
	br := bufio.NewReader(server)
	b, err := br.ReadByte()
	if err != nil {
		t.Fatal(err)
	}
	if b != 'a' {
		t.Fatalf("first byte = %q", b)
	}
	conn := &bufferedConn{Conn: server, r: br}
	got := make([]byte, 2)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "bc" {
		t.Fatalf("got %q", got)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
}
