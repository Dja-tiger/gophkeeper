// Package cli implements the cross-platform command-line interface without process exits.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/term"

	"github.com/Dja-tiger/gophkeeper/internal/buildinfo"
	"github.com/Dja-tiger/gophkeeper/internal/client"
	"github.com/Dja-tiger/gophkeeper/internal/model"
)

const help = `GophKeeper — encrypted private storage
Usage: gophkeeper COMMAND [flags]
Commands: register login logout add edit get list delete sync status resolve version
Common: --cache PATH --ca FILE --dev-http (loopback development only)
Auth: --server https://host:8443 --login NAME --auth-password-file FILE --vault-password-file FILE
      Passwords are prompted without echo when files are omitted. Minimum 12 bytes.
Records: --input JSON_FILE --id ID --file BINARY_FILE --output NEW_FILE --offline
         add/edit accept a full Secret JSON object; binary contents can come from --file.
Conflict: resolve --id ID --keep local|remote, then sync.
--offline uses the encrypted local cache; otherwise record commands synchronize first/after writes.
`

type options struct {
	cache, server, login, authFile, vaultFile, input, id, file, output, keep, ca string
	offline, dev                                                                 bool
}

// Run executes one CLI invocation. It returns errors to the caller and never prints secrets accidentally.
// out receives requested data; errOut receives help and password prompts. args exclude the program name.
func Run(ctx context.Context, args []string, out, errOut io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		_, e := io.WriteString(out, help)
		return e
	}
	command := args[0]
	if command == "version" || command == "--version" {
		_, e := fmt.Fprintf(out, "GophKeeper %s\nBuild date: %s\nCommit: %s\n", buildinfo.Version, buildinfo.Date, buildinfo.Commit)
		return e
	}
	switch command {
	case "register", "login", "logout", "add", "edit", "get", "list", "delete", "sync", "status", "resolve":
	default:
		return fmt.Errorf("unknown command %q; use help", command)
	}
	dir, e := os.UserConfigDir()
	if e != nil {
		return e
	}
	o := options{}
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	f.SetOutput(errOut)
	f.StringVar(&o.cache, "cache", filepath.Join(dir, "gophkeeper", "cache.json"), "encrypted cache path")
	f.StringVar(&o.server, "server", "https://localhost:8443", "server origin")
	f.StringVar(&o.login, "login", "", "account name")
	f.StringVar(&o.authFile, "auth-password-file", "", "authentication password file")
	f.StringVar(&o.vaultFile, "vault-password-file", "", "vault password file")
	f.StringVar(&o.ca, "ca", "", "trusted CA PEM file")
	f.StringVar(&o.input, "input", "", "secret JSON file")
	f.StringVar(&o.id, "id", "", "record ID")
	f.StringVar(&o.file, "file", "", "binary input path")
	f.StringVar(&o.output, "output", "", "new binary output path")
	f.StringVar(&o.keep, "keep", "", "local or remote")
	f.BoolVar(&o.offline, "offline", false, "use cache only")
	f.BoolVar(&o.dev, "dev-http", false, "allow loopback HTTP")
	if e = f.Parse(args[1:]); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	unlock, e := client.Lock(o.cache)
	if e != nil {
		return e
	}
	defer unlock()
	if command == "register" || command == "login" {
		return authenticate(ctx, command, o, out, errOut)
	}
	c, e := client.Load(o.cache)
	if e != nil {
		return fmt.Errorf("load cache (register or login first): %w", e)
	}
	if command == "status" {
		ids := make([]string, 0, len(c.Pending))
		for id := range c.Pending {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		return json.NewEncoder(out).Encode(map[string]any{"login": c.Session.Login, "server": c.Server, "pending": ids, "records": len(c.Records)})
	}
	r, e := remote(c.Server, o)
	if e != nil {
		return e
	}
	r.Token = c.Session.Token
	syncSave := func() error {
		syncErr := c.Sync(ctx, r)
		saveErr := c.Save(o.cache)
		return errors.Join(syncErr, saveErr)
	}
	if command == "sync" {
		if e = syncSave(); e != nil {
			return e
		}
		_, e = fmt.Fprintln(out, "Synchronized")
		return e
	}
	if command == "logout" {
		if e = r.Logout(ctx); e != nil {
			return e
		}
		c.Session.Token = ""
		return c.Save(o.cache)
	}
	if command == "delete" {
		if !o.offline {
			if e = syncSave(); e != nil {
				return e
			}
		}
		if e = c.Delete(o.id); e != nil {
			return e
		}
		if e = c.Save(o.cache); e != nil {
			return e
		}
		if !o.offline {
			return syncSave()
		}
		return nil
	}
	password, e := readPassword(o.vaultFile, "Vault password", errOut)
	if e != nil {
		return e
	}
	key, e := c.Unlock(password)
	if e != nil {
		return e
	}
	defer clear(key)
	if command == "resolve" {
		if e = c.Resolve(ctx, r, key, o.id, o.keep); e != nil {
			return e
		}
		return c.Save(o.cache)
	}
	if !o.offline {
		if e = syncSave(); e != nil {
			return e
		}
	}
	switch command {
	case "list":
		ids := make([]string, 0, len(c.Records))
		for id, v := range c.Records {
			if !v.Deleted {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		for _, id := range ids {
			s, e := c.Read(key, id)
			if e != nil {
				return e
			}
			if e = json.NewEncoder(out).Encode(map[string]string{"id": id, "type": s.Type, "title": s.Title, "metadata": s.Metadata}); e != nil {
				return e
			}
		}
		return nil
	case "get":
		s, e := c.Read(key, o.id)
		if e != nil {
			return e
		}
		if s.Type == "binary" {
			if o.output == "" {
				return errors.New("binary retrieval requires --output NEW_FILE")
			}
			return writeNew(o.output, s.Binary)
		}
		return json.NewEncoder(out).Encode(s)
	case "add", "edit":
		if o.input == "" {
			return errors.New("--input JSON_FILE required")
		}
		b, e := readLimited(o.input, model.MaxData)
		if e != nil {
			return e
		}
		var s model.Secret
		decoder := json.NewDecoder(strings.NewReader(string(b)))
		decoder.DisallowUnknownFields()
		if e = decoder.Decode(&s); e != nil {
			return e
		}
		if e = decoder.Decode(&struct{}{}); e != io.EOF {
			return errors.New("one secret JSON object required")
		}
		if o.file != "" {
			if s.Type != "binary" {
				return errors.New("--file is only valid for binary records")
			}
			s.Binary, e = readLimited(o.file, model.MaxFile)
			if e != nil {
				return e
			}
			s.Filename = filepath.Base(o.file)
		}
		if command == "edit" && o.id == "" {
			return errors.New("edit requires --id")
		}
		if command == "add" && o.id != "" {
			return errors.New("add generates its own ID")
		}
		id, e := c.Put(key, o.id, s)
		if e != nil {
			return e
		}
		if e = c.Save(o.cache); e != nil {
			return e
		}
		if _, e = fmt.Fprintln(out, id); e != nil {
			return e
		}
		if !o.offline {
			return syncSave()
		}
		return nil
	}
	return errors.New("unsupported command")
}
func remote(address string, o options) (*client.Remote, error) {
	var ca []byte
	var e error
	if o.ca != "" {
		ca, e = os.ReadFile(o.ca)
		if e != nil {
			return nil, e
		}
	}
	return client.NewRemote(address, o.dev, ca)
}
func authenticate(ctx context.Context, command string, o options, out, errOut io.Writer) error {
	if !model.ValidLogin(o.login) {
		return errors.New("--login must contain 3–64 letters, digits, dots, underscores or dashes")
	}
	r, e := remote(o.server, o)
	if e != nil {
		return e
	}
	existing, loadErr := client.Load(o.cache)
	if loadErr != nil && !errors.Is(loadErr, os.ErrNotExist) {
		return loadErr
	}
	if existing != nil && (command == "register" || existing.Server != r.URL || existing.Session.Login != o.login) {
		return errors.New("cache already belongs to an account; select a different --cache path")
	}
	auth, e := readPassword(o.authFile, "Authentication password", errOut)
	if e != nil {
		return e
	}
	password, e := readPassword(o.vaultFile, "Vault password", errOut)
	if e != nil {
		return e
	}
	if auth == password {
		return errors.New("authentication and vault passwords must be different")
	}
	credentials := model.Credentials{Login: o.login, Password: auth}
	var session model.Session
	if command == "register" {
		credentials.Salt, credentials.KeyCheck, e = client.VaultParameters(o.login, password)
		if e != nil {
			return e
		}
		session, e = r.Register(ctx, credentials)
	} else {
		session, e = r.Login(ctx, credentials)
	}
	if e != nil {
		return e
	}
	c := client.NewCache(r.URL, session)
	if existing != nil {
		c = existing
		c.Session = session
	}
	r.Token = session.Token
	key, e := c.Unlock(password)
	if e != nil {
		_ = r.Logout(ctx)
		return e
	}
	clear(key)
	// Persist session before synchronization so a transient network failure does not lose local work.
	if e = c.Save(o.cache); e != nil {
		return e
	}
	syncErr := c.Sync(ctx, r)
	saveErr := c.Save(o.cache)
	if e = errors.Join(syncErr, saveErr); e != nil {
		return e
	}
	_, e = fmt.Fprintln(out, "Authenticated and synchronized")
	return e
}
func readPassword(path, prompt string, out io.Writer) (string, error) {
	if path != "" {
		b, e := readLimited(path, 1024)
		if e != nil {
			return "", e
		}
		return strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r"), nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("password input requires a terminal or a password file")
	}
	fmt.Fprintf(out, "%s: ", prompt)
	b, e := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(out)
	return string(b), e
}
func readLimited(path string, max int) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if e != nil {
		return nil, e
	}
	if len(b) > max {
		return nil, errors.New("input file exceeds size limit")
	}
	return b, nil
}
func writeNew(path string, b []byte) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		os.Remove(path)
		return e
	}
	return f.Close()
}
