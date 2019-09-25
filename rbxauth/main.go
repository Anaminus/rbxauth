package main

import (
	"errors"
	"flag"
	"io"
	"os"
	"strings"

	"github.com/anaminus/but"
	"github.com/anaminus/rbxauth"
)

func main() {
	var input string
	var output string
	// var passwd string
	var cred rbxauth.Cred
	flag.StringVar(&input, "i", "", "Input stream as string. '\\n' becomes newline. Use stdin if empty.")
	flag.StringVar(&output, "o", "", "Path to output file. Write to stdout if empty.")
	flag.StringVar(&cred.Type, "t", "", "Credential type. Prompt if empty.")
	flag.StringVar(&cred.Ident, "u", "", "Credential identifier. Prompt if empty.")
	// flag.StringVar(&passwd, "p", "", "Password. Prompt if empty.")
	flag.Parse()

	var stream *rbxauth.Stream
	if input == "" {
		stream = rbxauth.StandardStream()
	} else {
		input = strings.ReplaceAll(input, "\\n", "\n")
		stream = &rbxauth.Stream{
			Reader: strings.NewReader(input),
			Writer: os.Stderr,
		}
	}

	cred, cookies, err := stream.PromptCred(cred)
	if errResp := (rbxauth.ErrorResponse{}); errors.As(err, &errResp) {
		but.IfFatal(errResp)
	}
	but.IfFatal(err)

	var w io.Writer
	if output == "" {
		w = os.Stdout
	} else {
		f, err := os.Create(output)
		but.IfFatal(err)
		defer f.Close()
		w = f
	}
	but.IfFatal(rbxauth.WriteCookies(w, cookies))
}
