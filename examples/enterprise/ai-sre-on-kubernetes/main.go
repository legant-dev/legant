// Command ai-sre is the host program for the "AI-SRE on real Kubernetes" enterprise
// demo. It has two roles:
//
//	ai-sre proxy   the Legant-guarded resource server in front of a REAL
//	               mcp-server-kubernetes (run by the orchestrator)
//	ai-sre agent   the AI-SRE agent that drives a real incident through the proxy
//
// See run.sh for the full orchestration (real kind cluster, real MCP server) and
// README.md for the narrative. This file holds the shared plumbing.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ai-sre <proxy|agent> [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "proxy":
		runProxy(os.Args[2:])
	case "agent":
		runAgent(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand:", os.Args[1])
		os.Exit(2)
	}
}

func newFlagSet(name string) *flag.FlagSet { return flag.NewFlagSet(name, flag.ExitOnError) }

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func asFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return 0
}

func oneline(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 64 {
		s = s[:64] + "…"
	}
	return s
}

func banner(s string) {
	line := strings.Repeat("=", 100)
	fmt.Println(line)
	fmt.Println("  " + s)
	fmt.Println(line)
}

func section(s string) {
	fmt.Println()
	fmt.Println("── " + s + " " + strings.Repeat("─", max(0, 92-len(s))))
}
