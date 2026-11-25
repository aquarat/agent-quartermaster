// Package docs embeds the agent guide so that `aqmas guide` and the MCP tool
// aqmas_guide print the text of the installed version.
package docs

import _ "embed"

// AgentGuide is docs/AGENTS.md.
//
//go:embed AGENTS.md
var AgentGuide string
