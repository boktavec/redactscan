package main

import (
	"fmt"
	"io"
	"log"
	"os"
)

var version = "dev"

func run(args []string, out io.Writer) error {
	if len(args) > 0 && args[0] == "version" {
		_, err := fmt.Fprintln(out, version)
		return err
	}
	_, err := fmt.Fprintln(out, "redactscan")
	return err
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		log.Fatal(err)
	}
}
