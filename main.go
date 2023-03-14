// Package main is responsible for the main func of sniproxy.  The actual work
// is done in the cmd package.
package main

import "github.com/ameshkov/sniproxy/internal/cmd"

func main() {
	cmd.Main()
}
