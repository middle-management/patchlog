package main

// Shell completion. patchlog completion bash|zsh|fish prints a script that
// asks patchlog itself for the candidates (patchlog __complete WORDS…), so
// completion follows the cli struct: commands, their subcommands and their
// flags, with no list to keep in step. Arguments and flag values fall back
// to the shell's file completion.

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
)

// completionCmd is patchlog completion SHELL.
type completionCmd struct {
	Shell string `arg:"positional,required" placeholder:"bash|zsh|fish" help:"the shell; e.g. source <(patchlog completion bash) in ~/.bashrc"`
}

func (a *completionCmd) run(string) {
	if err := writeCompletion(os.Stdout, a.Shell); err != nil {
		toolFatal(err)
	}
}

const bashCompletion = `# patchlog completion for bash: source <(patchlog completion bash)
_patchlog() {
	local IFS=$'\n'
	COMPREPLY=($(patchlog __complete "${COMP_WORDS[@]:1:COMP_CWORD}" 2>/dev/null))
}
complete -o default -F _patchlog patchlog
`

const zshCompletion = `#compdef patchlog
# patchlog completion for zsh: source <(patchlog completion zsh)
_patchlog() {
	local -a c
	c=("${(@f)$(patchlog __complete "${(@)words[2,CURRENT]}" 2>/dev/null)}")
	if (( ${#c[@]} )) && [[ -n "${c[1]}" ]]; then
		compadd -- "${c[@]}"
	else
		_files
	fi
}
compdef _patchlog patchlog
`

const fishCompletion = `# patchlog completion for fish: patchlog completion fish | source
complete -c patchlog -f -a '(patchlog __complete (commandline -opc)[2..-1] (commandline -ct))'
complete -c patchlog -F -n 'test -z (patchlog __complete (commandline -opc)[2..-1] (commandline -ct))'
`

func writeCompletion(w io.Writer, shell string) error {
	switch shell {
	case "bash":
		_, err := io.WriteString(w, bashCompletion)
		return err
	case "zsh":
		_, err := io.WriteString(w, zshCompletion)
		return err
	case "fish":
		_, err := io.WriteString(w, fishCompletion)
		return err
	}
	return fmt.Errorf("completion: no %q: bash, zsh or fish", shell)
}

// complete returns the completions of the last of words (the one being
// typed, maybe ""), given the words before it: the subcommands of the
// command they name, or with a leading dash its flags. Nothing (the
// shell's file completion) for a positional argument or a flag's value.
func complete(words []string) []string {
	if len(words) == 0 {
		words = []string{""}
	}
	t := reflect.TypeOf(cli{})
	prev := words[:len(words)-1]
	cur := words[len(words)-1]
	for i, w := range prev {
		if strings.HasPrefix(w, "-") {
			continue
		}
		if sub, ok := subcommandType(t, w); ok && !flagTakesValue(t, prev, i) {
			t = sub
		}
	}
	if len(prev) > 0 && flagTakesValue(t, prev, len(prev)) {
		return nil // the value of the flag before
	}
	var out []string
	if strings.HasPrefix(cur, "-") {
		for _, f := range flagNames(t) {
			if strings.HasPrefix(f, cur) {
				out = append(out, f)
			}
		}
		return out
	}
	for _, n := range subcommandNames(t) {
		if strings.HasPrefix(n, cur) {
			out = append(out, n)
		}
	}
	return out
}

// flagTakesValue reports whether words[i-1] is a flag of t that takes a
// value as the next word (not a bool, not --flag=value).
func flagTakesValue(t reflect.Type, words []string, i int) bool {
	if i == 0 {
		return false
	}
	w := words[i-1]
	if !strings.HasPrefix(w, "-") || strings.Contains(w, "=") {
		return false
	}
	f, ok := flagField(t, "--"+strings.TrimLeft(w, "-"))
	return ok && f.Type.Kind() != reflect.Bool
}

// walkFlags calls fn for each flag field of t, embedded structs included.
func walkFlags(t reflect.Type, fn func(f reflect.StructField, names []string)) {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			walkFlags(f.Type, fn)
			continue
		}
		tag := f.Tag.Get("arg")
		if strings.Contains(tag, "subcommand:") || strings.Contains(tag, "positional") || tag == "-" {
			continue
		}
		var names []string
		for _, p := range strings.Split(tag, ",") {
			if strings.HasPrefix(p, "-") {
				names = append(names, p)
			}
		}
		if !f.IsExported() || len(names) == 0 {
			continue
		}
		fn(f, names)
	}
}

func flagNames(t reflect.Type) []string {
	var out []string
	walkFlags(t, func(_ reflect.StructField, names []string) {
		for _, n := range names {
			if strings.HasPrefix(n, "--") {
				out = append(out, n)
			}
		}
	})
	return append(out, "--help", "--profile")
}

func flagField(t reflect.Type, name string) (reflect.StructField, bool) {
	var found reflect.StructField
	ok := false
	walkFlags(t, func(f reflect.StructField, names []string) {
		if !ok && (slices.Contains(names, name) || slices.Contains(names, strings.TrimPrefix(name, "-"))) {
			found, ok = f, true
		}
	})
	return found, ok
}

// subcommands are t's subcommand fields: name and struct type.
func subcommands(t reflect.Type) (names []string, types []reflect.Type) {
	if t.Kind() != reflect.Struct {
		return nil, nil
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		for _, p := range strings.Split(f.Tag.Get("arg"), ",") {
			if n, ok := strings.CutPrefix(p, "subcommand:"); ok && f.Type.Kind() == reflect.Pointer {
				names = append(names, strings.Split(n, "|")[0])
				types = append(types, f.Type.Elem())
			}
		}
	}
	return names, types
}

func subcommandNames(t reflect.Type) []string {
	names, _ := subcommands(t)
	return names
}

func subcommandType(t reflect.Type, name string) (reflect.Type, bool) {
	names, types := subcommands(t)
	if i := slices.Index(names, name); i >= 0 {
		return types[i], true
	}
	return nil, false
}
