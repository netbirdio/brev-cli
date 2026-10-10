package nbtunnel

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Credentials is what Brev's registration command carries for the netbird
// client: the one-off setup key and the management server to log in to.
type Credentials struct {
	SetupKey      string
	ManagementURL string
	Hostname      string
}

var errUnexpectedCommand = errors.New("unexpected registration command from Brev (expected 'netbird up ...')")

type credentialField int

const (
	fieldSetupKey credentialField = iota
	fieldManagementURL
	fieldHostname
)

// valueFlags maps every spelling of a netbird up flag we read to its field.
var valueFlags = map[string]credentialField{
	"--setup-key":      fieldSetupKey,
	"-k":               fieldSetupKey,
	"--key":            fieldSetupKey,
	"--management-url": fieldManagementURL,
	"-m":               fieldManagementURL,
	"--hostname":       fieldHostname,
	"-n":               fieldHostname,
}

// ParseRegistrationCommand extracts the credentials from the "netbird up ..."
// command Brev's AddNode RPC returns, so the embedded client can log in without
// running the command. Flags it does not know are ignored.
func ParseRegistrationCommand(command string) (Credentials, error) {
	fields := strings.Fields(strings.TrimSpace(command))
	if len(fields) < 2 || fields[0] != "netbird" || fields[1] != "up" {
		return Credentials{}, errUnexpectedCommand
	}
	creds, err := parseUpFlags(fields[2:])
	if err != nil {
		return Credentials{}, err
	}
	if err := creds.validate(); err != nil {
		return Credentials{}, err
	}
	return creds, nil
}

func parseUpFlags(args []string) (Credentials, error) {
	var creds Credentials
	for i := 0; i < len(args); i++ {
		name, value, inline := strings.Cut(args[i], "=")
		field, known := valueFlags[name]
		if !known {
			continue
		}
		if !inline {
			if i+1 >= len(args) {
				return Credentials{}, fmt.Errorf("registration command: flag %s has no value", name)
			}
			value = args[i+1]
			i++
		}
		creds.set(field, strings.Trim(value, `"'`))
	}
	return creds, nil
}

func (c *Credentials) set(field credentialField, value string) {
	switch field {
	case fieldSetupKey:
		c.SetupKey = value
	case fieldManagementURL:
		c.ManagementURL = value
	case fieldHostname:
		c.Hostname = value
	}
}

func (c Credentials) validate() error {
	if c.SetupKey == "" {
		return errors.New("registration command carries no setup key")
	}
	if c.ManagementURL == "" {
		return errors.New("registration command carries no management URL")
	}
	u, err := url.Parse(c.ManagementURL)
	if err != nil || u.Host == "" || u.Scheme != "https" {
		return fmt.Errorf("registration command has an invalid management URL %q (https required)", c.ManagementURL)
	}
	return nil
}
