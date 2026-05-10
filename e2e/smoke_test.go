// Package e2e tests CTFd_chat_notifier — solve / announcement events should
// produce HTTP POSTs to the configured Discord webhook.
//
// The plugin keeps its configuration in CTFd's Configs table, so changes are
// global; tests must not run in parallel and must restore the prior state.
package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/diver-osint-ctf/ctfd-plugin-e2e/testutil"
)

// mapToValues converts a string map into url.Values for form posts.
func mapToValues(m map[string]string) url.Values {
	v := url.Values{}
	for k, val := range m {
		v.Set(k, val)
	}
	return v
}

const (
	adminPath = "/admin/chat_notifier"
)

// applyConfig posts the chat_notifier admin form. CTFd routes Authorization:
// Token only on JSON requests, so an admin form post requires a session-
// authenticated client and a CSRF nonce harvested from the rendered form.
func applyConfig(t *testing.T, sess *testutil.Client, notifierType, webhookURL string, sendSolves, sendNotifications bool, msg string) {
	t.Helper()
	form := url.Values{}
	form.Set("notifier_type", notifierType)
	if sendSolves {
		form.Set("notifier_send_solves", "on")
	}
	if sendNotifications {
		form.Set("notifier_send_notifications", "on")
	}
	form.Set("notifier_solve_msg", msg)
	form.Set("notifier_solve_count", "")
	form.Set("notifier_discord_webhook_url", webhookURL)
	resp, err := sess.PostFormWithNonce(adminPath, form)
	if err != nil {
		t.Fatalf("apply chat_notifier config: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		t.Fatalf("apply chat_notifier config: HTTP %s", resp.Status)
	}
}

func TestChatNotifier_AdminPageLoads(t *testing.T) {
	admin := testutil.AdminClient(t)
	resp, err := admin.DoJSON(http.MethodGet, adminPath, nil, nil)
	if err != nil {
		t.Fatalf("GET %s: %v", adminPath, err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %s", resp.Status)
	}
}

// TestChatNotifier_PostsSolveToWebhook sets the webhook to a local mock,
// solves a challenge as a regular user, and asserts the mock received the
// expected payload.
func TestChatNotifier_PostsSolveToWebhook(t *testing.T) {
	admin := testutil.AdminClient(t)
	ns := testutil.Namespace(t)

	mock := testutil.NewDiscordMock(t)

	sess := testutil.AdminSessionClient(t)
	t.Cleanup(func() { applyConfig(t, sess, "", "", false, false, "") })
	applyConfig(t, sess, "discord", mock.ContainerURL(), true, true,
		"{solver} solved {challenge} ({solve_num})")

	user := testutil.CreateUser(t, admin, ns, 1)
	chal := testutil.CreateChallenge(t, admin, ns, "main", testutil.ChallengeStandard, testutil.ChallengeOpts{
		Flag:  "flag{notify_me}",
		Value: 100,
	})

	uc := testutil.UserClient(t, user.Name, user.Password)
	r := testutil.Submit(t, uc, chal.ID, "flag{notify_me}")
	if r.HTTPStatus != http.StatusOK || r.Status != "correct" {
		t.Fatalf("submit: expected 200/correct, got %d/%s", r.HTTPStatus, r.Status)
	}

	// First-blood path: solve_num=1 → embeds-based payload with title.
	got := mock.WaitFor(t, 5*time.Second)
	embeds, ok := got.Body["embeds"].([]any)
	if !ok || len(embeds) == 0 {
		t.Fatalf("expected embeds[] in payload, got %v", got.Body)
	}
	first, _ := embeds[0].(map[string]any)
	desc, _ := first["description"].(string)
	if !strings.Contains(desc, user.Name) {
		t.Errorf("description %q does not include user name %q", desc, user.Name)
	}
	if !strings.Contains(desc, chal.Name) {
		t.Errorf("description %q does not include challenge name %q", desc, chal.Name)
	}
}

// TestChatNotifier_NoWebhookWhenDisabled — solve must NOT trigger a webhook
// when notifier_send_solves is off.
func TestChatNotifier_NoWebhookWhenDisabled(t *testing.T) {
	admin := testutil.AdminClient(t)
	ns := testutil.Namespace(t)

	mock := testutil.NewDiscordMock(t)
	sess := testutil.AdminSessionClient(t)
	t.Cleanup(func() { applyConfig(t, sess, "", "", false, false, "") })
	applyConfig(t, sess, "discord", mock.ContainerURL(), false, false,
		"{solver} solved {challenge}")

	user := testutil.CreateUser(t, admin, ns, 1)
	chal := testutil.CreateChallenge(t, admin, ns, "main", testutil.ChallengeStandard, testutil.ChallengeOpts{
		Flag: "flag{quiet}",
	})
	uc := testutil.UserClient(t, user.Name, user.Password)
	r := testutil.Submit(t, uc, chal.ID, "flag{quiet}")
	if r.Status != "correct" {
		t.Fatalf("expected correct, got %q", r.Status)
	}
	select {
	case got := <-mock.Received:
		t.Fatalf("expected no webhook hit, got %v", got.Body)
	case <-time.After(2 * time.Second):
		// good
	}
}
