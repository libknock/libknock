// Package libknock provides embeddable TCP pre-application authentication for Go applications.
//
// libknock consumes a compact binary authentication frame immediately after TCP
// connect and returns a clean net.Conn to the caller. The caller can then start
// any application protocol that runs on top of net.Conn.
package libknock
