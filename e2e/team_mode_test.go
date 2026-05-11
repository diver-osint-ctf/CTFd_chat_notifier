// Coverage for the teams-mode branch of _send_solve_notification.
//
// When CTFd's user_mode is "teams" (or its localized form "チーム"), the
// solver string in the Discord payload should be formatted as
// "[user](url) ([team](url))" instead of just "[user](url)". user_mode
// is fixed at /setup time on the running CTFd instance, so this test
// skips when the instance is in users mode rather than trying to flip
// the global config mid-run.
package e2e

import (
	"strings"
	"testing"
	"time"

	"github.com/diver-osint-ctf/ctfd-plugin-e2e/testutil"
)

// TestChatNotifier_TeamModeIncludesTeamLink — payload's solver segment should
// embed the team's markdown link alongside the user's when teams mode is on.
func TestChatNotifier_TeamModeIncludesTeamLink(t *testing.T) {
	admin := testutil.AdminClient(t)
	sess := testutil.AdminSessionClient(t)
	ns := testutil.Namespace(t)

	// CreateUser auto-attaches a fresh team in teams mode and populates
	// TeamID; in users mode TeamID stays 0 and the team branch is
	// unreachable. Create the user before applying config to keep the
	// skip decision close to the assertion.
	user := testutil.CreateUser(t, admin, ns, 1)
	if user.TeamID == 0 {
		t.Skip("requires CTFd running in teams mode")
	}

	mock := testutil.NewDiscordMock(t)
	t.Cleanup(func() { applyConfig(t, sess, "", "", false, false, "") })
	applyConfig(t, sess, "discord", mock.ContainerURL(), true, false,
		"{solver} solved {challenge} ({solve_num})")

	chal := testutil.CreateChallenge(t, admin, ns, "main", testutil.ChallengeStandard, testutil.ChallengeOpts{
		Flag: "flag{team_mode}",
	})
	uc := testutil.UserClient(t, user.Name, user.Password)
	if r := testutil.Submit(t, uc, chal.ID, "flag{team_mode}"); r.Status != "correct" {
		t.Fatalf("submit: %s", r.Status)
	}

	got := mock.WaitFor(t, 5*time.Second)
	desc := payloadDescription(got.Body)
	// Teams-mode solver string: "[user](url) ([team](url))" — assert both
	// the user link and a "(" introducing the team segment are present.
	if !strings.Contains(desc, user.Name) {
		t.Errorf("expected user name %q in description, got %q", user.Name, desc)
	}
	// /teams/<id> URL is the team-link landing page that CTFd renders into the
	// payload via url_for("teams.public", ...).
	if !strings.Contains(desc, "/teams/") {
		t.Errorf("expected /teams/ link in team-mode payload, got %q", desc)
	}
}
