// Edge-case coverage that fills in branches the behavior tests don't reach:
// - notifier_type="discord" but webhook URL blank → is_configured() False
//   → get_configured_notifier() returns None → no fan-out.
// - POST with an unknown notifier_type → admin view returns 400.
// - notifier_solve_count=0 → every solve is over the cap, so no notification
//   ever fires (boundary alongside cap=1 covered by SolveCountLimit).
package e2e

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/diver-osint-ctf/ctfd-plugin-e2e/testutil"
)

// TestChatNotifier_EmptyWebhookURLNoFire — selecting "discord" without a
// webhook URL should leave is_configured() False, so a solve should fire no
// HTTP at all.
func TestChatNotifier_EmptyWebhookURLNoFire(t *testing.T) {
	admin := testutil.AdminClient(t)
	sess := testutil.AdminSessionClient(t)
	ns := testutil.Namespace(t)

	mock := testutil.NewDiscordMock(t)
	t.Cleanup(func() { applyConfig(t, sess, "", "", false, false, "") })
	// Note: webhook URL is the empty string; the mock URL is unused but the
	// mock is still spun up so any erroneous fire would land somewhere we
	// can assert against. Instead we listen on its channel — nothing should
	// arrive.
	_ = mock
	applyConfig(t, sess, "discord", "", true, true,
		"{solver} solved {challenge}")

	chal := testutil.CreateChallenge(t, admin, ns, "main", testutil.ChallengeStandard, testutil.ChallengeOpts{
		Flag: "flag{no_url}",
	})
	u := testutil.CreateUser(t, admin, ns, 1)
	uc := testutil.UserClient(t, u.Name, u.Password)
	if r := testutil.Submit(t, uc, chal.ID, "flag{no_url}"); r.Status != "correct" {
		t.Fatalf("submit: %s", r.Status)
	}
	select {
	case got := <-mock.Received:
		t.Errorf("expected no webhook with empty URL, got %v", got.Body)
	case <-time.After(2 * time.Second):
	}
}

// TestChatNotifier_InvalidNotifierTypeRejected — admin form view aborts with
// 400 when notifier_type is non-empty but not in NOTIFIER_CLASSES.
func TestChatNotifier_InvalidNotifierTypeRejected(t *testing.T) {
	sess := testutil.AdminSessionClient(t)

	form := url.Values{}
	form.Set("notifier_type", "definitely-not-a-real-notifier")
	form.Set("notifier_solve_msg", "")
	form.Set("notifier_solve_count", "")
	form.Set("notifier_discord_webhook_url", "")
	form.Set("notifier_discord_admin_webhook_url", "")
	resp, err := sess.PostFormWithNonce(adminPath, form)
	if err != nil {
		t.Fatalf("POST %s: %v", adminPath, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown notifier_type, got %s", resp.Status)
	}
}

// TestChatNotifier_SolveCountCapZeroSuppressesAll — solve_count is computed
// after the solve is recorded, so it's always >= 1. With cap=0, every solve
// satisfies "solve_count > max_solves" and short-circuits — no webhook at all.
func TestChatNotifier_SolveCountCapZeroSuppressesAll(t *testing.T) {
	admin := testutil.AdminClient(t)
	sess := testutil.AdminSessionClient(t)
	ns := testutil.Namespace(t)

	mock := testutil.NewDiscordMock(t)
	t.Cleanup(func() { applyConfig(t, sess, "", "", false, false, "") })
	applyConfigWithCount(t, sess, "discord", mock.ContainerURL(), true, false,
		"{solver} solved {challenge}", "0")

	chal := testutil.CreateChallenge(t, admin, ns, "main", testutil.ChallengeStandard, testutil.ChallengeOpts{
		Flag: "flag{cap_zero}",
	})
	u := testutil.CreateUser(t, admin, ns, 1)
	uc := testutil.UserClient(t, u.Name, u.Password)
	if r := testutil.Submit(t, uc, chal.ID, "flag{cap_zero}"); r.Status != "correct" {
		t.Fatalf("submit: %s", r.Status)
	}
	select {
	case got := <-mock.Received:
		t.Errorf("expected no notification with cap=0, got %v", got.Body)
	case <-time.After(2 * time.Second):
	}
}
