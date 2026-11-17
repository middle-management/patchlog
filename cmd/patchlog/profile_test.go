package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cleanEnv unsets the variables profiles and secret files read, for the
// test; they come back after it. Tests using it don't run in parallel.
func cleanEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"PATCHLOG_PROFILE", "PATCHLOG_CONFIG", "XDG_CONFIG_HOME", "PATCHLOG_API", "PATCHLOG_AUTHOR",
		"PATCHLOG_BEARER", "PATCHLOG_BEARER_FILE", "PATCHLOG_SIGN_KEY", "PATCHLOG_SIGN_KEY_FILE"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

// writeConfig writes a config file with profiles and points
// $PATCHLOG_CONFIG at it; it returns the directory.
func writeConfig(t *testing.T, profiles map[string]profile) string {
	t.Helper()
	dir := t.TempDir()
	b, _ := json.Marshal(configFile{Profiles: profiles})
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATCHLOG_CONFIG", path)
	return dir
}

func writeFile(t *testing.T, path, s string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestConfigPath(t *testing.T) {
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	home, _ := os.UserHomeDir()
	if got, want := configPath(get), filepath.Join(home, ".config", "patchlog", "config.json"); got != want {
		t.Errorf("default %s, want %s", got, want)
	}
	env["XDG_CONFIG_HOME"] = "/xdg"
	if got := configPath(get); got != "/xdg/patchlog/config.json" {
		t.Errorf("xdg %s", got)
	}
	env["PATCHLOG_CONFIG"] = "/etc/pl.json"
	if got := configPath(get); got != "/etc/pl.json" {
		t.Errorf("override %s", got)
	}
}

func TestExtractProfile(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		args       []string
		name, rest string
		err        bool
	}{
		{[]string{"get", "a/b"}, "", "get a/b", false},
		{[]string{"--profile", "work", "get", "a/b"}, "work", "get a/b", false},
		{[]string{"get", "a/b", "-profile=work", "--json"}, "work", "get a/b --json", false},
		{[]string{"get", "--profile=a", "--profile", "b"}, "b", "get", false},
		{[]string{"put", "a/b", "--", "--profile", "x"}, "", "put a/b -- --profile x", false},
		{[]string{"get", "--profile"}, "", "", true},
		{[]string{"get", "--profile="}, "", "", true},
	} {
		name, rest, err := extractProfile(tc.args)
		if (err != nil) != tc.err || name != tc.name || strings.Join(rest, " ") != tc.rest {
			t.Errorf("%q: %q %q %v, want %q %q err %v", tc.args, name, rest, err, tc.name, tc.rest, tc.err)
		}
	}
}

// getFlags is a client command's flags, to see what a profile gave them.
func getFlags(t *testing.T, args ...string) *getCmd {
	t.Helper()
	return command(t, append([]string{"get", "ns/x"}, args...)...).(*getCmd)
}

// TestProfilePrecedence: flag > environment > profile > built-in default.
func TestProfilePrecedence(t *testing.T) {
	cleanEnv(t)
	writeConfig(t, map[string]profile{
		"work": {API: "https://work.example", Author: "ann", BearerFile: "work.grant", SignKeyFile: "/keys/work"},
		"bare": {API: "https://bare.example"},
	})
	apply := func(args ...string) []string {
		t.Helper()
		rest, err := applyProfile(args)
		if err != nil {
			t.Fatal(err)
		}
		return rest
	}

	// No profile: the built-in default, and no config file is read.
	t.Setenv("PATCHLOG_CONFIG", filepath.Join(t.TempDir(), "missing.json"))
	if rest := apply("get", "ns/x"); len(rest) != 2 {
		t.Fatalf("rest %q", rest)
	}
	if a := getFlags(t).API; a != "http://localhost:8080" {
		t.Errorf("default api %q", a)
	}

	// The profile beats the default.
	dir := writeConfig(t, map[string]profile{
		"work": {API: "https://work.example", Author: "ann", BearerFile: "work.grant", SignKeyFile: "/keys/work"},
		"bare": {API: "https://bare.example"},
	})
	rest := apply("--profile", "work", "get", "ns/x")
	f := getFlags(t)
	if strings.Join(rest, " ") != "get ns/x" || f.API != "https://work.example" || f.Author != "ann" ||
		f.BearerFile != filepath.Join(dir, "work.grant") || f.SignKeyFile != "/keys/work" {
		t.Errorf("profile: rest %q flags %+v", rest, f.toolArgs)
	}

	// The environment beats the profile, a flag beats both.
	t.Setenv("PATCHLOG_API", "https://env.example")
	t.Setenv("PATCHLOG_AUTHOR", "env-author")
	f = getFlags(t)
	if f.API != "https://env.example" || f.Author != "env-author" {
		t.Errorf("env: %+v", f.toolArgs)
	}
	if f = getFlags(t, "--api", "https://flag.example"); f.API != "https://flag.example" {
		t.Errorf("flag: %+v", f.toolArgs)
	}

	// Anything the profile leaves out stays as it was.
	cleanEnv(t)
	t.Setenv("PATCHLOG_CONFIG", filepath.Join(dir, "config.json"))
	t.Setenv("PATCHLOG_PROFILE", "bare")
	apply("get", "ns/x")
	if f = getFlags(t); f.API != "https://bare.example" || f.Author != "" || f.BearerFile != "" {
		t.Errorf("bare: %+v", f.toolArgs)
	}
}

// TestProfileEnvironmentSelects: $PATCHLOG_PROFILE selects like --profile,
// which beats it; $PATCHLOG_BEARER, a grant given as a value, beats the
// profile's bearer_file.
func TestProfileEnvironmentSelects(t *testing.T) {
	cleanEnv(t)
	writeConfig(t, map[string]profile{"a": {API: "https://a.example", BearerFile: "/a.grant"}, "b": {API: "https://b.example"}})
	t.Setenv("PATCHLOG_PROFILE", "a")
	t.Setenv("PATCHLOG_BEARER", "TOKEN")
	if _, err := applyProfile([]string{"get", "ns/x"}); err != nil {
		t.Fatal(err)
	}
	if f := getFlags(t); f.API != "https://a.example" || f.Bearer != "TOKEN" || f.BearerFile != "" {
		t.Errorf("env profile: %+v", f.toolArgs)
	}
	os.Unsetenv("PATCHLOG_API")
	if _, err := applyProfile([]string{"--profile", "b", "get"}); err != nil {
		t.Fatal(err)
	}
	if f := getFlags(t); f.API != "https://b.example" {
		t.Errorf("flag profile: %+v", f.toolArgs)
	}
}

func TestProfileErrors(t *testing.T) {
	cleanEnv(t)
	// A profile that isn't there, with and without a config file.
	t.Setenv("PATCHLOG_CONFIG", filepath.Join(t.TempDir(), "none.json"))
	if _, err := applyProfile([]string{"--profile", "work", "get"}); err == nil || !strings.Contains(err.Error(), "no config file at") {
		t.Errorf("no config: %v", err)
	}
	writeConfig(t, map[string]profile{"a": {}, "b": {}})
	if _, err := applyProfile([]string{"--profile", "work", "get"}); err == nil || !strings.Contains(err.Error(), "profile work: not in") || !strings.Contains(err.Error(), "a, b") {
		t.Errorf("unknown: %v", err)
	}
	// A key the config doesn't know is a typo.
	path := filepath.Join(t.TempDir(), "typo.json")
	os.WriteFile(path, []byte(`{"profiles":{"w":{"bearer":"SECRET"}}}`), 0o600)
	t.Setenv("PATCHLOG_CONFIG", path)
	if _, err := applyProfile([]string{"--profile", "w", "get"}); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("typo: %v", err)
	}

	// Through run: exit status 2, on stderr.
	var out, errw bytes.Buffer
	if code := run([]string{"get", "--profile", "nope", "ns/x"}, &out, &errw); code != 2 || !strings.Contains(errw.String(), "profile nope") {
		t.Errorf("run: %d %q", code, errw.String())
	}
}

func TestProfileCommands(t *testing.T) {
	cleanEnv(t)
	writeConfig(t, map[string]profile{"work": {API: "https://work.example", Author: "ann"}, "home": {API: "https://home.example", BearerFile: "/h.grant"}})
	runOut := func(args ...string) (string, string, int) {
		var out, errw bytes.Buffer
		code := run(args, &out, &errw)
		return out.String(), errw.String(), code
	}
	// run's commands print to os.Stdout; the exec methods take a writer.
	var out bytes.Buffer
	if err := (&profileListCmd{}).exec(&out, os.Getenv); err != nil || out.String() != "  home             https://home.example\n  work             https://work.example\n" {
		t.Errorf("list: %v %q", err, out.String())
	}
	out.Reset()
	t.Setenv("PATCHLOG_PROFILE", "work")
	(&profileListCmd{}).exec(&out, os.Getenv)
	if !strings.Contains(out.String(), "* work") {
		t.Errorf("list marks the selection: %q", out.String())
	}
	out.Reset()
	if err := (&profileShowCmd{}).exec(&out, os.Getenv); err != nil || !strings.Contains(out.String(), "profile work (") || !strings.Contains(out.String(), "author         ann") {
		t.Errorf("show selected: %v %q", err, out.String())
	}
	out.Reset()
	if err := (&profileShowCmd{Name: "home", JSON: true}).exec(&out, os.Getenv); err != nil || !strings.Contains(out.String(), `"bearer_file": "/h.grant"`) {
		t.Errorf("show home: %v %q", err, out.String())
	}
	if err := (&profileShowCmd{Name: "nope"}).exec(&out, os.Getenv); err == nil {
		t.Error("an unknown profile was shown")
	}
	os.Unsetenv("PATCHLOG_PROFILE")
	if err := (&profileShowCmd{}).exec(&out, os.Getenv); err == nil || !strings.Contains(err.Error(), "which profile") {
		t.Errorf("show none: %v", err)
	}
	// The commands parse, and --profile works before them.
	for _, args := range [][]string{{"profile", "list"}, {"profile", "show", "work"}} {
		command(t, args...)
	}
	if _, _, code := runOut("--profile", "nope", "profile", "show", "work"); code != 0 {
		t.Errorf("profile show with --profile: %d", code)
	}
}

func TestBearerFile(t *testing.T) {
	cleanEnv(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "grant")
	writeFile(t, good, "  FILE-GRANT\n", 0o600)
	other := filepath.Join(dir, "other")
	writeFile(t, other, "OTHER\n", 0o600)
	resolve := func(args ...string) (*getCmd, string, error) {
		t.Helper()
		argv := append([]string{"get", "ns/x"}, args...)
		f := command(t, argv...).(*getCmd)
		var warn bytes.Buffer
		err := resolveSecretFiles(f, argv, &warn)
		return f, warn.String(), err
	}

	// --bearer-file, trimmed.
	f, warn, err := resolve("--bearer-file", good)
	if err != nil || f.Bearer != "FILE-GRANT" || warn != "" {
		t.Errorf("flag file: %q %q %v", f.Bearer, warn, err)
	}
	// Exclusive with --bearer on the command line.
	if _, _, err = resolve("--bearer", "X", "--bearer-file", good); err == nil || !strings.Contains(err.Error(), "--bearer and --bearer-file are exclusive") {
		t.Errorf("exclusive: %v", err)
	}
	if _, _, err = resolve("--sign-key=a:b", "-sign-key-file", good); err == nil || !strings.Contains(err.Error(), "--sign-key and --sign-key-file are exclusive") {
		t.Errorf("exclusive sign-key: %v", err)
	}
	// $PATCHLOG_BEARER loses to --bearer-file; $PATCHLOG_BEARER_FILE loses to --bearer.
	t.Setenv("PATCHLOG_BEARER", "ENV-GRANT")
	if f, _, err = resolve("--bearer-file", good); err != nil || f.Bearer != "FILE-GRANT" {
		t.Errorf("env bearer vs flag file: %q %v", f.Bearer, err)
	}
	if f, _, err = resolve(); err != nil || f.Bearer != "ENV-GRANT" {
		t.Errorf("env bearer alone: %q %v", f.Bearer, err)
	}
	os.Unsetenv("PATCHLOG_BEARER")
	t.Setenv("PATCHLOG_BEARER_FILE", other)
	if f, _, err = resolve("--bearer", "FLAG"); err != nil || f.Bearer != "FLAG" {
		t.Errorf("flag bearer vs env file: %q %v", f.Bearer, err)
	}
	// $PATCHLOG_BEARER_FILE alone, and --bearer-file over it; both in the
	// environment, the file wins.
	if f, _, err = resolve(); err != nil || f.Bearer != "OTHER" {
		t.Errorf("env file: %q %v", f.Bearer, err)
	}
	if f, _, err = resolve("--bearer-file", good); err != nil || f.Bearer != "FILE-GRANT" {
		t.Errorf("flag file vs env file: %q %v", f.Bearer, err)
	}
	t.Setenv("PATCHLOG_BEARER", "ENV-GRANT")
	if f, _, err = resolve(); err != nil || f.Bearer != "OTHER" {
		t.Errorf("env bearer vs env file: %q %v", f.Bearer, err)
	}
	os.Unsetenv("PATCHLOG_BEARER")
	os.Unsetenv("PATCHLOG_BEARER_FILE")

	// A file readable by others is warned about, an empty or missing one is an error.
	loose := filepath.Join(dir, "loose")
	writeFile(t, loose, "L\n", 0o644)
	if f, warn, err = resolve("--bearer-file", loose); err != nil || f.Bearer != "L" || !strings.Contains(warn, "may be read by others") {
		t.Errorf("loose: %q %q %v", f.Bearer, warn, err)
	}
	empty := filepath.Join(dir, "empty")
	writeFile(t, empty, "\n", 0o600)
	if _, _, err = resolve("--bearer-file", empty); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Errorf("empty: %v", err)
	}
	if _, _, err = resolve("--bearer-file", filepath.Join(dir, "nope")); err == nil {
		t.Error("a missing file was read")
	}

	// A profile's bearer_file, relative to the config file; a --bearer flag beats it.
	cfg := writeConfig(t, map[string]profile{"p": {BearerFile: "grant"}})
	writeFile(t, filepath.Join(cfg, "grant"), "PROFILE\n", 0o600)
	if _, err = applyProfile([]string{"--profile", "p", "get"}); err != nil {
		t.Fatal(err)
	}
	if f, _, err = resolve(); err != nil || f.Bearer != "PROFILE" {
		t.Errorf("profile file: %q %v", f.Bearer, err)
	}
	if f, _, err = resolve("--bearer", "FLAG"); err != nil || f.Bearer != "FLAG" {
		t.Errorf("flag vs profile file: %q %v", f.Bearer, err)
	}
	os.Unsetenv("PATCHLOG_BEARER_FILE")
	os.Unsetenv("PATCHLOG_API")
}

// TestBearerFileCommands: every command that takes --bearer takes
// --bearer-file, and dav keeps its own.
func TestBearerFileCommands(t *testing.T) {
	cleanEnv(t)
	for _, args := range [][]string{
		{"get", "ns/x"}, {"merge", "apply", "--branch", "b"}, {"janitor", "--ns", "n"}, {"tree", "--catalog", "c"}, {"index", "--ns", "n"},
		{"schema", "import", "--ns", "n", "x.json"}, {"export", "--ns", "n"}, {"import", "-i", "b"}, {"bundle", "verify", "-i", "b"},
		{"dav"}, {"grant", "check", "ns", "T"}, {"grant", "show", "ns", "G"},
		{"search", "ns", "q"}, {"tree", "ls", "cat"}, {"verify", "ns"},
	} {
		var c cli
		p, err := newParser(&c, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Parse(append(args, "--bearer-file", "/f")); err != nil {
			t.Errorf("%q: %v", args, err)
		}
	}
}
