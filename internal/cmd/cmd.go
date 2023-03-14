// Package cmd is responsible for the program's command-line interface.
package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ameshkov/sniproxy/internal/sniproxy"

	"github.com/AdguardTeam/golibs/log"
	"github.com/ameshkov/sniproxy/internal/dnsproxy"
	goFlags "github.com/jessevdk/go-flags"
)

// VersionString is the version that we'll print to the output. See the makefile
// for more details.
var VersionString = "undefined"

// Main is the entry point of the program.Ï
func Main() {
	for _, arg := range os.Args {
		if arg == "--version" {
			fmt.Printf("sniproxy version: %s\n", VersionString)
			os.Exit(0)
		}
	}

	options := &Options{}
	parser := goFlags.NewParser(options, goFlags.Default)
	_, err := parser.Parse()
	if err != nil {
		if flagsErr, ok := err.(*goFlags.Error); ok && flagsErr.Type == goFlags.ErrHelp {
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}

	if options.Verbose {
		log.SetLevel(log.DEBUG)
	}
	if options.LogOutput != "" {
		var file *os.File
		file, err = os.OpenFile(options.LogOutput, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			log.Fatalf("cannot create a log file: %s", err)
		}
		defer log.OnCloserError(file, log.INFO)
		log.SetOutput(file)
	}

	run(options)
}

// run starts reads the configuration options and starts the sniproxy.
func run(options *Options) {
	log.Info("cmd: run sniproxy with the following configuration:\n%s", options)

	dnsProxy := newDNSProxy(options)
	err := dnsProxy.Start()
	check(err)

	sniProxy := newSNIProxy(options)
	err = sniProxy.Start()
	check(err)

	// Subscribe to the OS events.
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGINT, syscall.SIGTERM)
	<-signalChannel

	log.Info("cmd: stopping sniproxy")
	log.OnCloserError(dnsProxy, log.INFO)
	log.OnCloserError(sniProxy, log.INFO)
}

// newDNSProxy creates a new instance of [*dnsproxy.DNSProxy] or panics if any
// error happens.
func newDNSProxy(options *Options) (d *dnsproxy.DNSProxy) {
	cfg := toDNSProxyConfig(options)

	d, err := dnsproxy.New(cfg)
	check(err)

	return d
}

// newSNIProxy creates a new instance of [*sniproxy.SNIProxy] or panics if any
// error happens.
func newSNIProxy(options *Options) (p *sniproxy.SNIProxy) {
	cfg := toSNIProxyConfig(options)

	p, err := sniproxy.New(cfg)
	check(err)

	return p
}

// check panics if err is not nil.
func check(err error) {
	if err != nil {
		panic(err)
	}
}
