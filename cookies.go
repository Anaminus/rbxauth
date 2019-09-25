package rbxauth

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
)

// ReadCookies parses cookies from r and returns a list of http.Cookies.
// Cookies are parsed as a number of "Set-Cookie" HTTP headers. Returns an
// empty list if the reader is empty.
func ReadCookies(r io.Reader) (cookies []*http.Cookie, err error) {
	// There's no direct way to parse cookies, so we have to cheat a little.
	h, err := textproto.NewReader(bufio.NewReader(r)).ReadMIMEHeader()
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("read cookies: %w", err)
	}
	resp := http.Response{Header: http.Header(h)}
	return resp.Cookies(), nil
}

// WriteCookies formats a list of cookies as a number of "Set-Cookie" HTTP
// headers and writes them to w.
func WriteCookies(w io.Writer, cookies []*http.Cookie) (err error) {
	// More cheating.
	h := http.Header{}
	for _, cookie := range cookies {
		h.Add("Set-Cookie", cookie.String())
	}
	if err = h.Write(w); err != nil {
		return fmt.Errorf("write cookies: %w", err)
	}
	return nil
}
