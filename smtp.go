package gomail

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// DialerOptions is a serializable struct containing all SMTP the options of
// the dialer to work.
type DialerOptions struct {
	// Host represents the host of the SMTP server.
	Host string `json:"host"`
	// Port represents the port of the SMTP server.
	Port int `json:"port"`
	// Username is the username to use to authenticate to the SMTP server.
	Username string `json:"username"`
	// Password is the password to use to authenticate to the SMTP server.
	Password string `json:"password"`
	// NativeTLS defines whether or not the client should use directly use a TLS
	// client (meaning: no STARTTLS)
	NativeTLS bool `json:"native_tls"`
	// DisableTLS defines whether or not the client should continue if the server
	// does not offer the ability to start a TLS connection.
	DisableTLS bool `json:"disable_tls"`
	// LocalName is the hostname sent to the SMTP server with the HELO command.
	// By default, "localhost" is sent.
	LocalName string `json:"local_name"`
}

// A Dialer is a dialer to an SMTP server.
type Dialer struct {
	opts *DialerOptions
	tls  *tls.Config

	deadline   time.Time
	okdeadline bool
}

// NewDialer returns a new SMTP Dialer with the specified options
func NewDialer(opts *DialerOptions) *Dialer {
	return &Dialer{opts: opts}
}

// NewDialerWithTLSConfig returns a new SMTP Dialer with the specified options.
// The specified tls configuration is used by the dialer to create the TLS
// client.
func NewDialerWithTLSConfig(opts *DialerOptions, tls *tls.Config) *Dialer {
	return &Dialer{opts: opts, tls: tls}
}

// SetDeadline adds a deadline to the dial process on all the i/o operations.
func (d *Dialer) SetDeadline(deadline time.Time) {
	d.deadline = deadline
	d.okdeadline = true
}

// Dial dials and authenticates to an SMTP server. The returned SendCloser
// should be closed when done using it.
func (d *Dialer) Dial() (closer SendCloser, err error) {
	if d.opts.DisableTLS && d.opts.NativeTLS {
		return nil,
			errors.New("gomail: bad options (asking for disable and native TLS is not permitted)")
	}

	timeout, err := d.checkDeadline()
	if err != nil {
		return nil, err
	}

	addr := net.JoinHostPort(d.opts.Host, strconv.Itoa(d.opts.Port))
	conn, err := netDialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	if d.opts.NativeTLS {
		conn = tlsClient(conn, d.tlsConfig())
	}

	if d.okdeadline {
		conn.SetDeadline(d.deadline)
	}

	c, err := smtpNewClient(conn, d.opts.Host)
	if err != nil {
		return nil, err
	}

	if d.opts.LocalName != "" {
		if err = c.Hello(d.opts.LocalName); err != nil {
			return nil, err
		}
	}

	startTLS := false
	if !d.opts.NativeTLS && !d.opts.DisableTLS {
		if startTLS, _ = c.Extension("STARTTLS"); !startTLS {
			return nil, errors.New("gomail: server does not offer the STARTTLS extension")
		}
	}
	if startTLS {
		if err := c.StartTLS(d.tlsConfig()); err != nil {
			return nil, err
		}
	}

	var auth smtp.Auth
	if d.opts.Username != "" || d.opts.Password != "" {
		if ok, auths := c.Extension("AUTH"); !ok {
			auth = nil
		} else if strings.Contains(auths, "CRAM-MD5") {
			auth = smtp.CRAMMD5Auth(
				d.opts.Username,
				d.opts.Password,
			)
		} else if strings.Contains(auths, "LOGIN") && !strings.Contains(auths, "PLAIN") {
			auth = &loginAuth{
				username: d.opts.Username,
				password: d.opts.Password,
				host:     d.opts.Host,
			}
		} else {
			auth = smtp.PlainAuth(
				"",
				d.opts.Username,
				d.opts.Password,
				d.opts.Host,
			)
		}
	}

	if auth != nil {
		if err = c.Auth(auth); err != nil {
			return nil, err
		}
	}

	return &smtpSender{c, d}, nil
}

func (d *Dialer) tlsConfig() *tls.Config {
	if d.tls == nil {
		return &tls.Config{ServerName: d.opts.Host}
	}
	return d.tls
}

func (d *Dialer) checkDeadline() (time.Duration, error) {
	var timeout time.Duration
	if d.okdeadline {
		timeout = d.deadline.Sub(time.Now())
		if timeout <= 0 {
			return 0, errors.New("gomail: timed out")
		}
	}
	return timeout, nil
}

// DialAndSend opens a connection to the SMTP server, sends the given emails and
// closes the connection.
func (d *Dialer) DialAndSend(m ...*Message) error {
	s, err := d.Dial()
	if err != nil {
		return err
	}
	defer s.Close()
	return Send(s, m...)
}

type smtpSender struct {
	smtpClient
	d *Dialer
}

func (c *smtpSender) Send(from string, to []string, msg io.WriterTo) error {
	if _, err := c.d.checkDeadline(); err != nil {
		return err
	}

	if err := c.Mail(from); err != nil {
		if err == io.EOF {
			// This is probably due to a timeout, so reconnect and try again.
			sc, derr := c.d.Dial()
			if derr == nil {
				if s, ok := sc.(*smtpSender); ok {
					*c = *s
					return c.Send(from, to, msg)
				}
			}
		}
		return err
	}

	for _, addr := range to {
		if err := c.Rcpt(addr); err != nil {
			return err
		}
	}

	w, err := c.Data()
	if err != nil {
		return err
	}

	if _, err = msg.WriteTo(w); err != nil {
		w.Close()
		return err
	}

	return w.Close()
}

func (c *smtpSender) Close() error {
	return c.Quit()
}

// Stubbed out for tests.
var (
	netDialTimeout = net.DialTimeout
	tlsClient      = tls.Client
	smtpNewClient  = func(conn net.Conn, host string) (smtpClient, error) {
		return smtp.NewClient(conn, host)
	}
)

type smtpClient interface {
	Hello(string) error
	Extension(string) (bool, string)
	StartTLS(*tls.Config) error
	Auth(smtp.Auth) error
	Mail(string) error
	Rcpt(string) error
	Data() (io.WriteCloser, error)
	Quit() error
	Close() error
}
