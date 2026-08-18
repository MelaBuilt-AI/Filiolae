package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"

	"golang.org/x/mod/sumdb/note"
)

func main() {
	privatePath := flag.String("private", "", "new mode-0600 synthetic private-key path")
	verifierPath := flag.String("verifier", "", "new mode-0644 verifier-key path")
	flag.Parse()
	if *privatePath == "" || *verifierPath == "" {
		fmt.Fprintln(os.Stderr, "both output paths are required")
		os.Exit(2)
	}
	secret, verifier, err := note.GenerateKey(rand.Reader, "filiolae.invalid/synthetic-s2/v1")
	if err != nil {
		panic(err)
	}
	pf, err := os.OpenFile(*privatePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		panic(err)
	}
	if _, err := fmt.Fprintln(pf, secret); err != nil {
		panic(err)
	}
	if err := pf.Sync(); err != nil {
		panic(err)
	}
	if err := pf.Close(); err != nil {
		panic(err)
	}
	vf, err := os.OpenFile(*verifierPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		_ = os.Remove(*privatePath)
		panic(err)
	}
	if _, err := fmt.Fprintln(vf, verifier); err != nil {
		panic(err)
	}
	if err := vf.Sync(); err != nil {
		panic(err)
	}
	if err := vf.Close(); err != nil {
		panic(err)
	}
}
