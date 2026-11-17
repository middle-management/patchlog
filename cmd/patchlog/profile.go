package main

// Connection profiles and secret files.
//
// A profile is a section of the config file (PATCHLOG_CONFIG, else
// $XDG_CONFIG_HOME/patchlog/config.json, else ~/.config/patchlog/config.json):
//
//	{"profiles": {"work": {"api": "https://pl.example", "author": "ann",
//	                       "bearer_file": "~/.config/patchlog/work.grant",
//	                       "sign_key_file": "~/.config/patchlog/work.key"}}}
//
// --profile NAME (anywhere on the command line) or $PATCHLOG_PROFILE selects
// one. Its values are defaults, applied before the command line is parsed
// by setting the PATCHLOG_* variable of each that is not set already, which
// go-arg then reads like any other. So the precedence is flag > environment
// > profile > built-in default. Secrets stay in files: a profile names
// bearer_file and sign_key_file, never the grant or the key.
//
// --bearer-file FILE ($PATCHLOG_BEARER_FILE) and --sign-key-file FILE
// ($PATCHLOG_SIGN_KEY_FILE) read the grant and the signing key from a
// file, trimmed, so they are not in the process arguments or the shell
// history. resolveSecretFiles does it after parsing.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// profile is one section of the config file.
type profile struct {
	API         string `json:"api,omitempty"`
	Author      string `json:"author,omitempty"`
	BearerFile  string `json:"bearer_file,omitempty"`
	SignKeyFile string `json:"sign_key_file,omitempty"`
}

// configFile is the config file.
type configFile struct {
	Profiles map[string]profile `json:"profiles"`
}

// configPath is the config file: $PATCHLOG_CONFIG, else
// $XDG_CONFIG_HOME/patchlog/config.json, else ~/.config/patchlog/config.json.
func configPath(getenv func(string) string) string {
	if p := getenv("PATCHLOG_CONFIG"); p != "" {
		return p
	}
	if x := getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "patchlog", "config.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "~"
	}
	return filepath.Join(home, ".config", "patchlog", "config.json")
}

// loadConfig reads the config file at path. Unknown keys are an error, to
// catch a misspelled one.
func loadConfig(path string) (*configFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("no config file at %s", path)
		}
		return nil, err
	}
	var c configFile
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

// lookupProfile returns the profile name from the config file at path.
func lookupProfile(path, name string) (profile, error) {
	c, err := loadConfig(path)
	if err != nil {
		return profile{}, fmt.Errorf("profile %s: %w", name, err)
	}
	p, ok := c.Profiles[name]
	if !ok {
		return profile{}, fmt.Errorf("profile %s: not in %s (it has %s)", name, path, nameList(c.Profiles))
	}
	return p, nil
}

func nameList(m map[string]profile) string {
	if len(m) == 0 {
		return "no profiles"
	}
	return strings.Join(sortedNames(m), ", ")
}

func sortedNames(m map[string]profile) []string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// flagGiven reports whether the flag name (without dashes) is on the command
// line, as -name or --name, with or without =VALUE, before any --.
func flagGiven(args []string, name string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		a = strings.TrimLeft(a, "-")
		if a == name || strings.HasPrefix(a, name+"=") {
			return true
		}
	}
	return false
}

// extractProfile removes --profile NAME (or --profile=NAME, or the
// single-dash spellings) from args, wherever it is before a --, and returns
// NAME ("" if absent). The last one wins, as with other flags.
func extractProfile(args []string) (name string, rest []string, err error) {
	rest = make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			rest = append(rest, args[i:]...)
			break
		}
		t := strings.TrimLeft(a, "-")
		switch {
		case len(a) > len(t) && t == "profile":
			if i+1 >= len(args) {
				return "", nil, errors.New("--profile needs a name")
			}
			i++
			name = args[i]
		case len(a) > len(t) && strings.HasPrefix(t, "profile="):
			name = strings.TrimPrefix(t, "profile=")
		default:
			rest = append(rest, a)
		}
	}
	if name == "" && len(rest) != len(args) {
		return "", nil, errors.New("--profile: empty name")
	}
	return name, rest, nil
}

// expandHome resolves p against the config file's directory, and ~/.
func expandHome(p, dir string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, p[1:])
		}
	}
	if p != "" && !filepath.IsAbs(p) {
		return filepath.Join(dir, p)
	}
	return p
}

// profileEnv is the environment of profile p of the config file at path:
// the variables it defines that lookup doesn't have, bearer_file also not
// when $PATCHLOG_BEARER is set, nor sign_key_file when $PATCHLOG_SIGN_KEY
// is (the environment beats the profile, and a grant or key given as a value
// beats one in a file).
func profileEnv(p profile, path string, lookup func(string) (string, bool)) map[string]string {
	dir := filepath.Dir(path)
	env := map[string]string{}
	set := func(k, v string, unless ...string) {
		if v == "" {
			return
		}
		for _, u := range append(unless, k) {
			if _, ok := lookup(u); ok {
				return
			}
		}
		env[k] = v
	}
	set("PATCHLOG_API", p.API)
	set("PATCHLOG_AUTHOR", p.Author)
	if p.BearerFile != "" {
		set("PATCHLOG_BEARER_FILE", expandHome(p.BearerFile, dir), "PATCHLOG_BEARER")
	}
	if p.SignKeyFile != "" {
		set("PATCHLOG_SIGN_KEY_FILE", expandHome(p.SignKeyFile, dir), "PATCHLOG_SIGN_KEY")
	}
	return env
}

// selectedProfile is the profile named by --profile, else $PATCHLOG_PROFILE;
// args are returned without --profile.
func selectedProfile(args []string, getenv func(string) string) (name string, rest []string, err error) {
	name, rest, err = extractProfile(args)
	if err != nil {
		return "", nil, err
	}
	if name == "" {
		name = getenv("PATCHLOG_PROFILE")
	}
	return name, rest, nil
}

// applyProfile sets the environment of the selected profile, if any, and
// returns args without --profile. A missing config file is an error only
// when a profile is selected.
func applyProfile(args []string) ([]string, error) {
	name, rest, err := selectedProfile(args, os.Getenv)
	if err != nil || name == "" {
		return rest, err
	}
	// profile list and show read the selection themselves.
	os.Setenv("PATCHLOG_PROFILE", name)
	if len(rest) > 0 && rest[0] == "profile" {
		return rest, nil
	}
	path := configPath(os.Getenv)
	p, err := lookupProfile(path, name)
	if err != nil {
		return nil, err
	}
	lookup := func(k string) (string, bool) { return os.LookupEnv(k) }
	for k, v := range profileEnv(p, path, lookup) {
		os.Setenv(k, v)
	}
	return rest, nil
}

// secretFiles are the pairs of a secret flag and the flag naming its file.
var secretFiles = []struct{ field, fileField, flag, fileFlag string }{
	{"Bearer", "BearerFile", "bearer", "bearer-file"},
	{"SignKey", "SignKeyFile", "sign-key", "sign-key-file"},
}

// resolveSecretFiles fills the --bearer and --sign-key of cmd from their
// files, --bearer-file and --sign-key-file, whether given as flags or
// through the environment, which args are the command line of. Giving both
// the flag and its file flag on the command line is an error. Otherwise a
// flag beats everything (a --bearer on the command line ignores a
// $PATCHLOG_BEARER_FILE), and a file beats a value from the environment,
// $PATCHLOG_BEARER: that the file is named is the more deliberate choice,
// and a --bearer-file flag must win over it. A file readable by others is
// warned about on warn.
func resolveSecretFiles(cmd any, args []string, warn io.Writer) error {
	v := reflect.ValueOf(cmd)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		return nil
	}
	v = v.Elem()
	for _, s := range secretFiles {
		if flagGiven(args, s.flag) && flagGiven(args, s.fileFlag) {
			return fmt.Errorf("--%s and --%s are exclusive", s.flag, s.fileFlag)
		}
		val, file := v.FieldByName(s.field), v.FieldByName(s.fileField)
		if !val.IsValid() || !file.IsValid() || file.String() == "" || flagGiven(args, s.flag) {
			continue
		}
		secret, err := readSecretFile("--"+s.fileFlag, file.String(), warn)
		if err != nil {
			return err
		}
		val.SetString(secret)
	}
	return nil
}

// readSecretFile reads a grant or key from a file, without surrounding
// white space, warning on warn if others can read it.
func readSecretFile(flagName, file string, warn io.Writer) (string, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("%s: %w", flagName, err)
	}
	if fi, err := os.Stat(file); err == nil && loose(fi) && warn != nil {
		fmt.Fprintf(warn, "patchlog: warning: %s %s may be read by others (mode %v); chmod 600 it\n", flagName, file, fi.Mode().Perm())
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", fmt.Errorf("%s: %s is empty", flagName, file)
	}
	return s, nil
}

// profileCmd is patchlog profile list|show.
type profileCmd struct {
	List *profileListCmd `arg:"subcommand:list" help:"list the profiles of the config file"`
	Show *profileShowCmd `arg:"subcommand:show" help:"show a profile: the defaults it gives and the config file it is in"`
}

type profileListCmd struct {
	JSON bool `arg:"--json" help:"print JSON"`
}

type profileShowCmd struct {
	JSON bool   `arg:"--json" help:"print JSON"`
	Name string `arg:"positional" placeholder:"NAME" help:"the profile (default the one --profile or $PATCHLOG_PROFILE selects)"`
}

func (a *profileListCmd) run(string) {
	if err := a.exec(os.Stdout, os.Getenv); err != nil {
		toolFatal(err)
	}
}

func (a *profileShowCmd) run(string) {
	if err := a.exec(os.Stdout, os.Getenv); err != nil {
		toolFatal(err)
	}
}

func (a *profileListCmd) exec(out io.Writer, getenv func(string) string) error {
	path := configPath(getenv)
	c, err := loadConfig(path)
	if err != nil {
		return err
	}
	if a.JSON {
		return writeJSON(out, map[string]any{"config": path, "profiles": sortedNames(c.Profiles)})
	}
	sel := getenv("PATCHLOG_PROFILE")
	for _, n := range sortedNames(c.Profiles) {
		mark := " "
		if n == sel {
			mark = "*"
		}
		fmt.Fprintf(out, "%s %-16s %s\n", mark, n, c.Profiles[n].API)
	}
	return nil
}

func (a *profileShowCmd) exec(out io.Writer, getenv func(string) string) error {
	name := a.Name
	if name == "" {
		name = getenv("PATCHLOG_PROFILE")
	}
	if name == "" {
		return errors.New("which profile? give NAME, --profile or $PATCHLOG_PROFILE")
	}
	path := configPath(getenv)
	p, err := lookupProfile(path, name)
	if err != nil {
		return err
	}
	if a.JSON {
		return writeJSON(out, map[string]any{"name": name, "config": path, "profile": p})
	}
	fmt.Fprintf(out, "profile %s (%s)\n", name, path)
	for _, kv := range [][2]string{{"api", p.API}, {"author", p.Author}, {"bearer_file", p.BearerFile}, {"sign_key_file", p.SignKeyFile}} {
		if kv[1] != "" {
			fmt.Fprintf(out, "  %-14s %s\n", kv[0], kv[1])
		}
	}
	return nil
}
