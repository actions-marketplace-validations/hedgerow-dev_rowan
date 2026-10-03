// Command server is the entry point for the Oracle Go app
// (benchmark/ground_truth/ai_apps/go, JG-11). Source only -- this module is
// never built or run, only scanned. See ground_truth.yaml in this directory
// for the labeled answer key.
package main

import (
	"database/sql"
	"log"

	"github.com/mark3labs/mcp-go/server"

	"github.com/hedgerow/oracle-go/internal/tools"
)

func main() {
	db, err := sql.Open("postgres", "postgres://oracle:oracle@localhost/oracle?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}

	s := server.NewMCPServer("oracle-go", "0.1.0")
	tools.RegisterAll(s, db)

	go startDebugServer(s)

	// G-09 (tnt-go-ai-mcpbind-001): the primary SSE transport listens on all
	// interfaces with no auth middleware -- WithHTTPContextFunc is never set.
	sse := server.NewSSEServer(s)
	if err := sse.Start("0.0.0.0:8080"); err != nil {
		log.Fatal(err)
	}
}

// GD-03: the debug/admin transport is bound to loopback only, so a
// scanner that understands bind-address should not flag it the way it
// flags the 0.0.0.0 SSE transport above.
func startDebugServer(s *server.MCPServer) {
	debug := server.NewSSEServer(s)
	if err := debug.Start("127.0.0.1:9090"); err != nil {
		log.Println("debug server exited:", err)
	}
}
