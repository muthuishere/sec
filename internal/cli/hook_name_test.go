package cli

import "testing"

func TestNotSecretName(t *testing.T) {
	for _, n := range []string{"DOCKER_USERNAME", "acme/api@dev:SMTP_HOST", "ADMIN_EMAIL", "AWS_REGION", "DB_USER", "GCP_PROJECT_ID"} {
		if !notSecretName(n) {
			t.Errorf("%s should be treated as an identifier", n)
		}
	}
	for _, n := range []string{"DOCKER_PASSWORD", "STRIPE_KEY", "DB_PASSWORD", "USER_TOKEN", "GITHUB_TOKEN"} {
		if notSecretName(n) {
			t.Errorf("%s is a credential", n)
		}
	}
}
