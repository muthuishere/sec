package detect

import "testing"

func TestReferencesAreNotSecrets(t *testing.T) {
	for _, line := range []string{
		"ANTHROPIC_API_KEY: sec:CLAUDE_200_API_KEY",
		"x-api-key: sec:CLAUDE_200_API_KEY",
		"API_KEY: sec:billing@prod:STRIPE_KEY",
		"API_KEY=env:OPENAI_API_KEY",
		"DB_PASSWORD: dotenv:DB_PASSWORD",
		"TOKEN: ${GITHUB_TOKEN}",
		"TOKEN: ${sec:GITHUB_TOKEN}",
		"TOKEN=$GITHUB_TOKEN",
		"SECRET: {{SECRET}}",
	} {
		if h := Find(line, nil); len(h) != 0 {
			t.Errorf("%q flagged as %s", line, h[0].Name)
		}
	}
	for _, line := range []string{"API_KEY: sk_live_abcdef1234567890", "API_KEY: secret:hunter2hunter2"} {
		if len(Find(line, nil)) == 0 {
			t.Errorf("%q not flagged", line)
		}
	}
}
