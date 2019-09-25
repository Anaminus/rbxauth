package rbxauth

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

// Stream uses a io.Reader and an optional io.Writer to perform an interactive
// login.
type Stream struct {
	Config
	io.Reader
	io.Writer
}

// write prints to Writer if it exists.
func (s *Stream) write(a ...interface{}) (n int, err error) {
	if s.Writer == nil {
		return 0, nil
	}
	return fmt.Fprint(s.Writer, a...)
}

// write printfs to Writer if it exists.
func (s *Stream) writef(format string, a ...interface{}) (n int, err error) {
	if s.Writer == nil {
		return 0, nil
	}
	return fmt.Fprintf(s.Writer, format, a...)
}

// PromptCred prompts a user to login through the specified input stream.
// Handles multi-step verification, if necessary. If cred.Type and/or cred.Ident
// are empty, then they will be prompted as well.
//
// Returns the updated cred and cookies, or any error that may have occurred.
func (s *Stream) PromptCred(cred Cred) (credout Cred, cookies []*http.Cookie, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("prompt: %w", err)
		}
	}()
	if s.Reader == nil {
		return cred, nil, errors.New("stream is missing reader")
	}

	switch cred.Type {
	case "Username", "Email", "PhoneNumber", "":
	default:
		return cred, nil, fmt.Errorf("invalid credential type %q", cred.Type)
	}

	scanner := bufio.NewScanner(s.Reader)
	scanner.Split(bufio.ScanLines)

	// Prompt for credential type.
	for cred.Type == "" {
		s.write("Enter credential type ((Username), Email, PhoneNumber): ")
		if scanner.Scan(); scanner.Err() != nil {
			return cred, nil, scanner.Err()
		}
		cred.Type = strings.ToLower(scanner.Text())
		switch cred.Type {
		case "username", "user", "u", "":
			cred.Type = "Username"
		case "email", "e":
			cred.Type = "Email"
		case "phonenumber", "phone number", "pn":
			cred.Type = "PhoneNumber"
		default:
			// TODO: maybe support whatever was entered, for forward
			// compatibility with the API.
			s.writef("Unknown credential type %q\n", cred.Type)
			cred.Type = ""
		}
	}

	// Prompt for identifier.
	for cred.Ident == "" {
		var msg string
		switch cred.Type {
		case "Username":
			msg = "Enter username: "
		case "Email":
			msg = "Enter email: "
		case "PhoneNumber":
			msg = "Enter phone number: "
		default:
			msg = "Enter " + cred.Type + ": "
		}
		s.write(msg)
		if scanner.Scan(); scanner.Err() != nil {
			return cred, nil, scanner.Err()
		}
		cred.Ident = scanner.Text()
	}

	// Prompt for password.
	s.writef("Enter password for %s: ", cred.Ident)
	var password []byte
	if s.Reader == os.Stdin {
		// Safely read from stdin.
		password, err = terminal.ReadPassword(int(syscall.Stdin))
		os.Stdout.Write([]byte{'\n'})
		if err != nil {
			return cred, nil, err
		}
	} else {
		// Fallback to scan.
		if scanner.Scan(); scanner.Err() != nil {
			return cred, nil, scanner.Err()
		}
		password = scanner.Bytes()
	}

	// Login.
	cookies, step, err := s.Config.LoginCred(cred, password)
	if err != nil {
		return cred, nil, err
	}

	if step != nil {
		var code string
		var remember bool

		// Prompt for verification code.
		s.writef("Two-step verification code sent via %s\n", step.MediaType)
		for {
			s.write("Enter code (leave empty to resend): ")
			if scanner.Scan(); scanner.Err() != nil {
				return cred, nil, scanner.Err()
			}
			if code = scanner.Text(); code != "" {
				break
			}
			if err := step.Resend(); err != nil {
				return cred, nil, err
			}
			s.writef("Resent verification code via %s\n", step.MediaType)
		}

		// Prompt for remember device.
	loop:
		for {
			s.write("Remember device? ((no), yes): ")
			if scanner.Scan(); scanner.Err() != nil {
				return cred, nil, scanner.Err()
			}
			switch text := strings.ToLower(scanner.Text()); text {
			case "y", "yes":
				remember = true
				break loop
			case "n", "no", "":
				break loop
			}
		}

		// Verify code.
		if cookies, err = step.Verify(code, remember); err != nil {
			return cred, nil, err
		}
	}

	return cred, cookies, nil
}

// Prompt wraps PromptCred, using a username for the credentials. If the
// username is empty, it will also be prompted.
func (s *Stream) Prompt(username string) (cred Cred, cookies []*http.Cookie, err error) {
	if username != "" {
		cred.Type = "Username"
		cred.Ident = username
	}
	return s.PromptCred(cred)
}

// PromptID wraps PromptCred, deriving credentials from the given user ID. If
// the ID is less then 1, then it will also be prompted.
//
// Note that an initial request must be made in order to associate the ID with
// its corresponding credentials.
func (s *Stream) PromptID(userID int64) (cred Cred, cookies []*http.Cookie, err error) {
	if userID < 1 {
		if s.Reader != nil {
			return cred, nil, fmt.Errorf("prompt: %w", errors.New("stream is missing reader"))
		}
		scanner := bufio.NewScanner(s.Reader)
		scanner.Split(bufio.ScanLines)
	}

	url := s.Config.UserIDEndpoint
	if url == "" {
		url = DefaultUserIDEndpoint
	}
	username, err := s.getUsername(userID)
	if err != nil {
		return Cred{}, nil, fmt.Errorf("prompt: %w", err)
	}
	return s.PromptCred(Cred{Type: "Username", Ident: username})
}

// StandardStream returns a Stream connected to stdin and stderr.
func StandardStream() *Stream {
	return &Stream{
		Reader: os.Stdin,
		Writer: os.Stderr,
	}
}
