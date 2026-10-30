// Package skills carries the agent skill inside the sec binary, so
// `sec skill install` works on any machine — including one sec was just
// streamed onto — without the source tree.
package skills

import _ "embed"

//go:embed sec/SKILL.md
var SecSkill []byte
