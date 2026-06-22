// Package mcpauth implements the MCP / OAuth 2.1 authorization surface:
// RFC 8707 resource indicators, RFC 9728 protected-resource metadata, and the
// RFC 6750/9728 WWW-Authenticate challenges resource servers return.
package mcpauth

import (
	"fmt"
	"net/url"
	"strings"
)

// CanonicalizeResource validates and canonicalizes an RFC 8707 resource
// indicator. The resource must be an absolute URI, https (or http only for
// loopback in dev), with no fragment; the scheme and host are lowercased and a
// default port removed so that semantically-equal resources compare equal and a
// resource-server audience cannot be confused by trivial string variations.
func CanonicalizeResource(raw string) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("resource is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid resource URI: %w", err)
	}
	if !u.IsAbs() || u.Host == "" {
		return "", fmt.Errorf("resource must be an absolute URI with a host")
	}
	if u.Fragment != "" {
		return "", fmt.Errorf("resource must not contain a fragment")
	}
	if u.User != nil {
		return "", fmt.Errorf("resource must not contain userinfo")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Host)
	if scheme != "https" && !(scheme == "http" && isLoopback(u.Hostname())) {
		return "", fmt.Errorf("resource must use https")
	}
	host = stripDefaultPort(scheme, host)

	u.Scheme = scheme
	u.Host = host
	// Treat "https://host" and "https://host/" as the same resource — the most
	// common real-world resource-indicator form mismatch.
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

// ResourceMatches reports whether a requested resource matches an allowed one
// after canonicalization. A resource that fails to canonicalize never matches.
func ResourceMatches(requested, allowed string) bool {
	rc, err := CanonicalizeResource(requested)
	if err != nil {
		return false
	}
	ac, err := CanonicalizeResource(allowed)
	if err != nil {
		return false
	}
	return rc == ac
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func stripDefaultPort(scheme, host string) string {
	switch {
	case scheme == "https" && strings.HasSuffix(host, ":443"):
		return strings.TrimSuffix(host, ":443")
	case scheme == "http" && strings.HasSuffix(host, ":80"):
		return strings.TrimSuffix(host, ":80")
	}
	return host
}
