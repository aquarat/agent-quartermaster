package main

import (
	"regexp"
	"strings"
)

// Per-command help: "aqmas CMD --help", "aqmas CMD -h", "aqmas CMD help" and "aqmas help CMD"
// print the lines of the usage text that describe CMD, and a usage error says where to
// look. The usage text stays the one place the syntax is written down.

// ownHelp are commands that answer --help themselves (cf has its own help page; set has
// per-subcommand help).
var ownHelp = map[string]bool{"cf": true, "set": true}

// helpCommand is the command being run, for the hint on a usage error.
var helpCommand string

var usageNames = regexp.MustCompile(`aqmas ([a-z][a-z-]*(?:\s*\|\s*[a-z][a-z-]*)*)`)

// commandUsage returns the blocks of the usage text that describe cmd (an alias finds its
// command's block): a block is a line "  aqmas ..." and the more-indented lines under it.
func commandUsage(cmd string) (string, bool) {
	var out []string
	in := false
	for _, line := range strings.Split(usage, "\n") {
		switch {
		case strings.HasPrefix(line, "  aqmas "):
			in = false
			for _, m := range usageNames.FindAllStringSubmatch(line, -1) {
				for _, name := range strings.Split(m[1], "|") {
					if strings.TrimSpace(name) == cmd {
						in = true
					}
				}
			}
		case !strings.HasPrefix(line, "      "):
			in = false
		}
		if in {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		return "", false
	}
	return "Usage:\n" + strings.Join(out, "\n") + "\n\nExamples and what each error means: aqmas guide. All commands: aqmas help.\n", true
}

// wantsHelp reports whether args (the words after the command) ask for its help: a first
// word help, -h or --help, or -h / --help as the last word before "--" (or the end) when the
// word before it is not a flag. So "aqmas run P --why --help -- cmd" is not help: there
// --help may be the value of --why, and the command is parsed (and refused) as written.
func wantsHelp(args []string) bool {
	if len(args) > 0 && (args[0] == "help" || args[0] == "-h" || args[0] == "--help") {
		return true
	}
	end := len(args)
	for i, a := range args {
		if a == "--" {
			end = i
			break
		}
	}
	if end == 0 {
		return false
	}
	last := args[end-1]
	return end >= 2 && (last == "--help" || last == "-h") && !strings.HasPrefix(args[end-2], "-")
}

// usageHint is appended to a usage error's message.
func usageHint() string {
	if _, ok := commandUsage(helpCommand); ok && !ownHelp[helpCommand] {
		return " (see: aqmas " + helpCommand + " --help)"
	}
	if helpCommand == "cf" {
		return " (see: aqmas cf help)"
	}
	if helpCommand == "set" {
		return "" // set's own usage errors already say where to look
	}
	return " (see: aqmas help)"
}
