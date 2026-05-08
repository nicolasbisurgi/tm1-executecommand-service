package command

import (
	"reflect"
	"testing"
)

func TestParseCommand(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantWrap ShellWrapper
		wantExec string
		wantArgs []string
		wantErr  bool
	}{
		// bare executable
		{"bare exec no args", `C:\Scripts\foo.bat`, ShellNone, `C:\Scripts\foo.bat`, nil, false},
		{"bare exec with args", `C:\Scripts\foo.bat a b`, ShellNone, `C:\Scripts\foo.bat`, []string{"a", "b"}, false},
		{"bare exec extra spaces", `  C:\Scripts\foo.bat   a   b  `, ShellNone, `C:\Scripts\foo.bat`, []string{"a", "b"}, false},

		// cmd /C wrapper
		{"cmd /C wrapper", `cmd /C C:\Scripts\foo.bat a`, ShellCmdC, `C:\Scripts\foo.bat`, []string{"a"}, false},
		{"cmd /C case-insensitive", `Cmd /c C:\Scripts\foo.bat`, ShellCmdC, `C:\Scripts\foo.bat`, nil, false},
		{"cmd /C uppercase", `CMD /C C:\Scripts\foo.bat`, ShellCmdC, `C:\Scripts\foo.bat`, nil, false},
		{"cmd.exe /C wrapper", `cmd.exe /C C:\Scripts\foo.bat`, ShellCmdC, `C:\Scripts\foo.bat`, nil, false},

		// powershell -File wrapper
		{"powershell -File", `powershell -File C:\Scripts\foo.ps1 a`, ShellPowerShellFile, `C:\Scripts\foo.ps1`, []string{"a"}, false},
		{"powershell.exe -File", `powershell.exe -File C:\Scripts\foo.ps1`, ShellPowerShellFile, `C:\Scripts\foo.ps1`, nil, false},
		{"powershell -file lowercase", `powershell -file C:\Scripts\foo.ps1`, ShellPowerShellFile, `C:\Scripts\foo.ps1`, nil, false},

		// quoted paths (Windows convention)
		{"quoted exec path with spaces", `"C:\Program Files\Foo\bar.bat" a`, ShellNone, `C:\Program Files\Foo\bar.bat`, []string{"a"}, false},
		{"quoted exec under cmd /C", `cmd /C "C:\Program Files\Foo\bar.bat" arg`, ShellCmdC, `C:\Program Files\Foo\bar.bat`, []string{"arg"}, false},
		{"quoted arg preserved as single token", `C:\Scripts\foo.bat "arg with space"`, ShellNone, `C:\Scripts\foo.bat`, []string{"arg with space"}, false},
		{"adjacent quoted and unquoted concatenate", `"C:\foo"\bar.bat`, ShellNone, `C:\foo\bar.bat`, nil, false},

		// interpreter-then-script (current behavior preserved by policy via findScriptToken)
		{"interpreter then script", `python C:\Scripts\foo.py`, ShellNone, "python", []string{`C:\Scripts\foo.py`}, false},

		// /C in argument position must NOT trigger wrapper detection
		{"slash-C as argument is not a wrapper", `myprog.exe /C something`, ShellNone, "myprog.exe", []string{"/C", "something"}, false},

		// errors
		{"empty input", ``, ShellNone, "", nil, true},
		{"whitespace only", `   `, ShellNone, "", nil, true},
		{"unbalanced opening quote", `"foo`, ShellNone, "", nil, true},
		{"cmd /C alone after trim", `cmd /C   `, ShellNone, "", nil, true},
		{"cmd /C exact match", `cmd /C`, ShellNone, "", nil, true},
		{"powershell wrapper with no exec", `powershell -File   `, ShellNone, "", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := ParseCommand(tt.raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseCommand(%q) err = %v, wantErr %v", tt.raw, err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if cmd.Wrapper != tt.wantWrap {
				t.Errorf("Wrapper = %v, want %v", cmd.Wrapper, tt.wantWrap)
			}
			if cmd.Executable != tt.wantExec {
				t.Errorf("Executable = %q, want %q", cmd.Executable, tt.wantExec)
			}
			if !reflect.DeepEqual(cmd.Args, tt.wantArgs) {
				t.Errorf("Args = %v, want %v", cmd.Args, tt.wantArgs)
			}
			if cmd.Raw != tt.raw {
				t.Errorf("Raw = %q, want %q", cmd.Raw, tt.raw)
			}
		})
	}
}

func TestShellWrapperString(t *testing.T) {
	tests := []struct {
		w    ShellWrapper
		want string
	}{
		{ShellNone, "none"},
		{ShellCmdC, "cmd /C"},
		{ShellPowerShellFile, "powershell -File"},
	}
	for _, tt := range tests {
		if got := tt.w.String(); got != tt.want {
			t.Errorf("ShellWrapper(%d).String() = %q, want %q", tt.w, got, tt.want)
		}
	}
}
