// Package command owns the parsed representation of a command-line execution
// request and (in Phase 2) the executor seam that runs it. Parsing and policy
// evaluation share this single canonical structure so the raw command line is
// never re-parsed downstream.
package command

import (
	"fmt"
	"strings"
)

// ShellWrapper records whether the customer wrapped their command in `cmd /C`
// or `powershell -File`. It is preserved (not silently stripped) so the
// executor can re-emit the original shape.
type ShellWrapper int

const (
	ShellNone ShellWrapper = iota
	ShellCmdC
	ShellPowerShellFile
)

func (w ShellWrapper) String() string {
	switch w {
	case ShellCmdC:
		return "cmd /C"
	case ShellPowerShellFile:
		return "powershell -File"
	default:
		return "none"
	}
}

// Command is the parsed form of a single execution request.
//
//   - Wrapper:    cmd /C, powershell -File, or none.
//   - Executable: first token after any wrapper, with surrounding quotes
//     stripped. May be a script (foo.bat) or an interpreter (python).
//   - Args:       remaining tokens, in original order. Quoted args remain
//     a single element.
//   - Raw:        the original input. Retained for logging and shell-meta
//     scanning.
type Command struct {
	Wrapper    ShellWrapper
	Executable string
	Args       []string
	Raw        string
}

type wrapperPrefix struct {
	prefix  string
	wrapper ShellWrapper
}

// Order matters: longer prefixes (`.exe`) must precede shorter ones to avoid
// the shorter form swallowing the `.exe` suffix into the executable token.
var wrapperPrefixes = []wrapperPrefix{
	{"cmd.exe /c ", ShellCmdC},
	{"cmd /c ", ShellCmdC},
	{"powershell.exe -file ", ShellPowerShellFile},
	{"powershell -file ", ShellPowerShellFile},
}

// ParseCommand parses a raw command line into a Command. It honours
// double-quoted tokens (Windows convention) so paths with spaces survive,
// detects shell wrappers case-insensitively, and rejects unbalanced quotes
// or wrappers with no executable body.
func ParseCommand(raw string) (Command, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return Command{}, fmt.Errorf("empty command")
	}

	lower := strings.ToLower(trimmed)
	wrapper := ShellNone
	remainder := trimmed

	for _, wp := range wrapperPrefixes {
		bare := strings.TrimRight(wp.prefix, " ")
		if lower == bare {
			return Command{}, fmt.Errorf("command has wrapper %q but no executable", wp.wrapper)
		}
		if strings.HasPrefix(lower, wp.prefix) {
			wrapper = wp.wrapper
			remainder = strings.TrimSpace(trimmed[len(wp.prefix):])
			if remainder == "" {
				return Command{}, fmt.Errorf("command has wrapper %q but no executable", wp.wrapper)
			}
			break
		}
	}

	tokens, err := tokenize(remainder)
	if err != nil {
		return Command{}, err
	}
	if len(tokens) == 0 {
		return Command{}, fmt.Errorf("command has no executable")
	}

	var args []string
	if len(tokens) > 1 {
		args = tokens[1:]
	}

	return Command{
		Wrapper:    wrapper,
		Executable: tokens[0],
		Args:       args,
		Raw:        raw,
	}, nil
}

// tokenize splits s into tokens, honouring double-quote-delimited segments.
// Quotes are stripped from emitted tokens; adjacent quoted/unquoted runs
// concatenate into a single token (Windows CMD convention).
// An unclosed quote returns an error.
func tokenize(s string) ([]string, error) {
	var tokens []string
	var current strings.Builder
	inQuote := false
	hasContent := false

	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
			hasContent = true
		case !inQuote && (r == ' ' || r == '\t'):
			if hasContent {
				tokens = append(tokens, current.String())
				current.Reset()
				hasContent = false
			}
		default:
			current.WriteRune(r)
			hasContent = true
		}
	}

	if inQuote {
		return nil, fmt.Errorf("unbalanced double-quote in command")
	}
	if hasContent {
		tokens = append(tokens, current.String())
	}

	return tokens, nil
}
