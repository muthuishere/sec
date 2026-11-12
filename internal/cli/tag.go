package cli

import (
	"fmt"
	"strings"

	"github.com/muthuishere/secure-agent/internal/owner"
)

func init() {
	register("tag", "tag NAME a,b[,c] [--add] — set (or add to) the tags (projects, categories) of a secret or file", cmdTag)
	docs["tag"] = helpDoc{group: "store",
		syntax:   []string{"sec tag NAME a,b[,c]          replace the tags", "sec tag NAME c --add          add tags"},
		examples: []string{"sec tag SA_JSON reqsume,firebase", "sec tag STRIPE_KEY liveconv --add"},
		next:     "sec ls --tag T  ·  sec file ls --tag T  ·  sec file add PATH --tag a,b"}
}

func cmdTag(args []string) error {
	add := false
	var pos []string
	for _, a := range args {
		if a == "--add" {
			add = true
			continue
		}
		pos = append(pos, a)
	}
	if len(pos) != 2 {
		return fmt.Errorf("usage: sec tag NAME a,b[,c] [--add]")
	}
	s, err := open()
	if err != nil {
		return err
	}
	m, err := s.Meta(pos[0])
	if err != nil {
		return fmt.Errorf("no secret %s", pos[0])
	}
	t := splitList(pos[1])
	if add {
		seen := map[string]bool{}
		for _, x := range m.Tags {
			seen[x] = true
		}
		for _, x := range t {
			if !seen[x] {
				m.Tags = append(m.Tags, x)
			}
		}
	} else {
		m.Tags = t
	}
	if err := s.SaveMeta(m); err != nil {
		return err
	}
	s.Audit("tag", owner.Agent(), []string{pos[0]}, map[string]string{"tags": strings.Join(m.Tags, ",")})
	fmt.Printf("✓ %s tags = %s\n", pos[0], strings.Join(m.Tags, ","))
	return nil
}
