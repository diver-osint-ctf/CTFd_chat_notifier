// Admin-form persistence tests: every field saved via the admin form must
// round-trip through the rendered HTML, and a blank notifier_solve_count must
// be honoured as "unlimited" (i.e. set_config(None)) rather than collapsing
// to zero or some default.
package e2e

import (
	"io"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/diver-osint-ctf/ctfd-plugin-e2e/testutil"
)

func fetchAdminHTML(t *testing.T, sess *testutil.Client) string {
	t.Helper()
	resp, err := sess.HTTP.Get(sess.BaseURL + adminPath)
	if err != nil {
		t.Fatalf("get admin page: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read admin page: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin page: HTTP %s", resp.Status)
	}
	return string(body)
}

// isCheckboxChecked returns true if <input id="<id>" ... checked ...> is rendered.
func isCheckboxChecked(html, id string) bool {
	re := regexp.MustCompile(`(?s)id="` + regexp.QuoteMeta(id) + `"([^>]*)>`)
	m := re.FindStringSubmatch(html)
	if m == nil {
		return false
	}
	return regexp.MustCompile(`\bchecked\b`).MatchString(m[1])
}

// extractInputValue pulls value="..." from <input id="<id>" ... value="...">.
// Returns "" if the input has no value attribute (templates omit it when the
// underlying config is None).
func extractInputValue(html, id string) string {
	re := regexp.MustCompile(`(?s)id="` + regexp.QuoteMeta(id) + `"[^>]*?value="([^"]*)"`)
	m := re.FindStringSubmatch(html)
	if m == nil {
		return ""
	}
	return m[1]
}

// extractSelectedOption returns the inner text of the <option selected> under
// <select id="<id>">. Returns "" when nothing is selected (the first option).
func extractSelectedOption(html, id string) string {
	selectRE := regexp.MustCompile(`(?s)<select[^>]*id="` + regexp.QuoteMeta(id) + `"[^>]*>(.*?)</select>`)
	sel := selectRE.FindStringSubmatch(html)
	if sel == nil {
		return ""
	}
	optRE := regexp.MustCompile(`(?s)<option\s+selected[^>]*>(.*?)</option>`)
	m := optRE.FindStringSubmatch(sel[1])
	if m == nil {
		return ""
	}
	return m[1]
}

// TestChatNotifier_AdminFormReflectsSavedSettings — POST a non-default config
// then GET the admin HTML and confirm every input echoes the saved value.
// Covers select, checkboxes, text inputs, the per-notifier extension inputs
// (discord webhook URLs), and the solve_count number input.
func TestChatNotifier_AdminFormReflectsSavedSettings(t *testing.T) {
	sess := testutil.AdminSessionClient(t)
	t.Cleanup(func() { applyConfig(t, sess, "", "", false, false, "") })

	const (
		wantWebhook      = "https://discord.com/api/webhooks/111/aaa"
		wantAdminWebhook = "https://discord.com/api/webhooks/222/bbb"
		wantMsg          = "{solver} just popped {challenge}"
		wantCount        = "5"
	)
	applyConfigFull(t, sess, "discord", wantWebhook, wantAdminWebhook,
		true, true, wantMsg, wantCount)

	html := fetchAdminHTML(t, sess)

	if got := extractSelectedOption(html, "notifier_type"); got != "discord" {
		t.Errorf("notifier_type selected option=%q, want \"discord\"", got)
	}
	if !isCheckboxChecked(html, "notifier_send_solves") {
		t.Error("notifier_send_solves checkbox should be checked")
	}
	if !isCheckboxChecked(html, "notifier_send_notifications") {
		t.Error("notifier_send_notifications checkbox should be checked")
	}
	if got := extractInputValue(html, "notifier_solve_msg"); got != wantMsg {
		t.Errorf("notifier_solve_msg=%q, want %q", got, wantMsg)
	}
	if got := extractInputValue(html, "notifier_solve_count"); got != wantCount {
		t.Errorf("notifier_solve_count=%q, want %q", got, wantCount)
	}
	if got := extractInputValue(html, "notifier_discord_webhook_url"); got != wantWebhook {
		t.Errorf("notifier_discord_webhook_url=%q, want %q", got, wantWebhook)
	}
	if got := extractInputValue(html, "notifier_discord_admin_webhook_url"); got != wantAdminWebhook {
		t.Errorf("notifier_discord_admin_webhook_url=%q, want %q", got, wantAdminWebhook)
	}
}

// TestChatNotifier_AdminFormUncheckedFlagsRoundTrip — POSTing the form with
// neither send_solves nor send_notifications set must persist as "off" and
// the next GET must not show them checked. Verifies the standard HTML form
// quirk (unchecked boxes are absent from the POST body) doesn't silently
// preserve the previous value.
func TestChatNotifier_AdminFormUncheckedFlagsRoundTrip(t *testing.T) {
	sess := testutil.AdminSessionClient(t)
	t.Cleanup(func() { applyConfig(t, sess, "", "", false, false, "") })

	// Turn them on first.
	applyConfig(t, sess, "discord", "https://discord.com/api/webhooks/x/y",
		true, true, "{solver}")
	if html := fetchAdminHTML(t, sess); !isCheckboxChecked(html, "notifier_send_solves") {
		t.Fatal("precondition: expected send_solves to be checked after enabling")
	}

	// Now turn them off.
	applyConfig(t, sess, "discord", "https://discord.com/api/webhooks/x/y",
		false, false, "{solver}")
	html := fetchAdminHTML(t, sess)
	if isCheckboxChecked(html, "notifier_send_solves") {
		t.Error("notifier_send_solves should be unchecked after disabling")
	}
	if isCheckboxChecked(html, "notifier_send_notifications") {
		t.Error("notifier_send_notifications should be unchecked after disabling")
	}
}

// TestChatNotifier_BlankSolveCountMeansUnlimited — admin.py converts a blank
// notifier_solve_count to None (= "no cap"). With it blank, every solve on a
// challenge — well beyond the small numbers in the cap tests — should still
// fan out a webhook. Guards against a regression where blank silently
// collapses to 0 (which would suppress everything).
func TestChatNotifier_BlankSolveCountMeansUnlimited(t *testing.T) {
	admin := testutil.AdminClient(t)
	sess := testutil.AdminSessionClient(t)
	ns := testutil.Namespace(t)

	mock := testutil.NewDiscordMock(t)
	t.Cleanup(func() { applyConfig(t, sess, "", "", false, false, "") })

	// count = "" → admin.py persists None → notifier sends for every solve.
	applyConfigWithCount(t, sess, "discord", mock.ContainerURL(),
		true, false, "{solver} solved {challenge}", "")

	// Verify the rendered form really does show an empty value (the template
	// omits the value attribute when the config is None).
	html := fetchAdminHTML(t, sess)
	if got := extractInputValue(html, "notifier_solve_count"); got != "" {
		t.Fatalf("notifier_solve_count after blank POST: form value=%q, want empty", got)
	}

	chal := testutil.CreateChallenge(t, admin, ns, "main", testutil.ChallengeStandard, testutil.ChallengeOpts{
		Flag:  "flag{ok}",
		Value: 100,
	})

	const solvers = 4
	for i := 1; i <= solvers; i++ {
		u := testutil.CreateUser(t, admin, ns, i)
		uc := testutil.UserClient(t, u.Name, u.Password)
		r := testutil.Submit(t, uc, chal.ID, "flag{ok}")
		if r.HTTPStatus != http.StatusOK || r.Status != "correct" {
			t.Fatalf("solver %d: expected 200/correct, got %d/%s", i, r.HTTPStatus, r.Status)
		}
	}

	// Drain the mock briefly to allow the (synchronous in plugin) webhook
	// posts to land, then count.
	got := 0
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && got < solvers {
		select {
		case <-mock.Received:
			got++
		case <-time.After(200 * time.Millisecond):
		}
	}
	if got != solvers {
		t.Errorf("expected %d webhooks (one per solver, no cap), got %d", solvers, got)
	}
}
