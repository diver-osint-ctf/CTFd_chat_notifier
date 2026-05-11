// Tests for the first-blood-only "admin webhook" routing.
//
// notifier_discord_admin_webhook_url is an optional secondary webhook that
// should receive a duplicate of the first-blood embed (and nothing else).
// These tests use two DiscordMock instances — one for the public channel and
// one for the staff/admin channel — to assert per-mock fan-out behavior.
package e2e

import (
	"strings"
	"testing"
	"time"

	"github.com/diver-osint-ctf/ctfd-plugin-e2e/testutil"
)

// TestChatNotifier_FirstBloodFansOutToAdminWebhook — when an admin webhook
// URL is configured, the first solve fires the embed payload on both the
// public webhook and the admin webhook.
func TestChatNotifier_FirstBloodFansOutToAdminWebhook(t *testing.T) {
	admin := testutil.AdminClient(t)
	sess := testutil.AdminSessionClient(t)
	ns := testutil.Namespace(t)

	publicMock := testutil.NewDiscordMock(t)
	adminMock := testutil.NewDiscordMock(t)
	t.Cleanup(func() { applyConfig(t, sess, "", "", false, false, "") })
	applyConfigFull(t, sess, "discord",
		publicMock.ContainerURL(), adminMock.ContainerURL(),
		true, true, "{solver} solved {challenge} ({solve_num})", "")

	chal := testutil.CreateChallenge(t, admin, ns, "main", testutil.ChallengeStandard, testutil.ChallengeOpts{
		Flag: "flag{fb_admin}",
	})
	user := testutil.CreateUser(t, admin, ns, 1)
	uc := testutil.UserClient(t, user.Name, user.Password)
	if r := testutil.Submit(t, uc, chal.ID, "flag{fb_admin}"); r.Status != "correct" {
		t.Fatalf("submit: %s", r.Status)
	}

	pub := publicMock.WaitFor(t, 5*time.Second)
	adm := adminMock.WaitFor(t, 5*time.Second)

	for label, body := range map[string]map[string]any{"public": pub.Body, "admin": adm.Body} {
		embeds, ok := body["embeds"].([]any)
		if !ok || len(embeds) == 0 {
			t.Fatalf("%s webhook: expected embeds[], got %v", label, body)
		}
		first, _ := embeds[0].(map[string]any)
		title, _ := first["title"].(string)
		if !strings.Contains(title, "First Blood") {
			t.Errorf("%s webhook: expected First Blood title, got %q", label, title)
		}
		if c, _ := first["color"].(float64); int(c) != 15158332 {
			t.Errorf("%s webhook: expected color 15158332, got %v", label, first["color"])
		}
	}
}

// TestChatNotifier_AdminWebhookSilentOnRegularSolve — non-first-blood solves
// must NOT hit the admin webhook. The public webhook still receives the
// regular content payload as usual.
func TestChatNotifier_AdminWebhookSilentOnRegularSolve(t *testing.T) {
	admin := testutil.AdminClient(t)
	sess := testutil.AdminSessionClient(t)
	ns := testutil.Namespace(t)

	publicMock := testutil.NewDiscordMock(t)
	adminMock := testutil.NewDiscordMock(t)
	t.Cleanup(func() { applyConfig(t, sess, "", "", false, false, "") })
	applyConfigFull(t, sess, "discord",
		publicMock.ContainerURL(), adminMock.ContainerURL(),
		true, true, "{solver} solved {challenge} ({solve_num})", "")

	chal := testutil.CreateChallenge(t, admin, ns, "main", testutil.ChallengeStandard, testutil.ChallengeOpts{
		Flag: "flag{fb_admin_only}",
	})

	// First solver — first blood, expected to fan out.
	u1 := testutil.CreateUser(t, admin, ns, 1)
	uc1 := testutil.UserClient(t, u1.Name, u1.Password)
	_ = testutil.Submit(t, uc1, chal.ID, "flag{fb_admin_only}")
	_ = publicMock.WaitFor(t, 5*time.Second)
	_ = adminMock.WaitFor(t, 5*time.Second)

	// Second solver — public still receives, admin must stay silent.
	u2 := testutil.CreateUser(t, admin, ns, 2)
	uc2 := testutil.UserClient(t, u2.Name, u2.Password)
	_ = testutil.Submit(t, uc2, chal.ID, "flag{fb_admin_only}")

	got := publicMock.WaitFor(t, 5*time.Second)
	if _, hasEmbeds := got.Body["embeds"]; hasEmbeds {
		t.Errorf("regular solve on public webhook should not carry embeds, got %v", got.Body)
	}
	if c, _ := got.Body["content"].(string); !strings.Contains(c, "2nd") {
		t.Errorf("expected '2nd' in public content, got %q", c)
	}

	select {
	case got := <-adminMock.Received:
		t.Errorf("admin webhook should not receive non-first-blood solve, got %v", got.Body)
	case <-time.After(2 * time.Second):
	}
}

// TestChatNotifier_AdminWebhookSilentOnAnnouncement — announcements use
// notify_message, which is NOT a first-blood event and must never reach the
// admin webhook regardless of the broadcast settings.
func TestChatNotifier_AdminWebhookSilentOnAnnouncement(t *testing.T) {
	admin := testutil.AdminClient(t)
	sess := testutil.AdminSessionClient(t)

	publicMock := testutil.NewDiscordMock(t)
	adminMock := testutil.NewDiscordMock(t)
	t.Cleanup(func() { applyConfig(t, sess, "", "", false, false, "") })
	applyConfigFull(t, sess, "discord",
		publicMock.ContainerURL(), adminMock.ContainerURL(),
		false, true, "", "")

	announcement := map[string]any{
		"title":   "Heads up",
		"content": "fresh hint posted",
		"type":    "toast",
		"sound":   true,
	}
	resp, err := admin.PostJSON("/api/v1/notifications", announcement, nil)
	if err != nil {
		t.Fatalf("post notification: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		t.Fatalf("post notification: HTTP %s", resp.Status)
	}

	// Public should receive the announcement embed.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case got := <-publicMock.Received:
			embeds, _ := got.Body["embeds"].([]any)
			if len(embeds) > 0 {
				if e, ok := embeds[0].(map[string]any); ok {
					if title, _ := e["title"].(string); title == "Heads up" {
						goto checkAdmin
					}
				}
			}
		case <-deadline:
			t.Fatalf("public announcement embed not received")
		}
	}

checkAdmin:
	select {
	case got := <-adminMock.Received:
		t.Errorf("admin webhook should not receive announcements, got %v", got.Body)
	case <-time.After(2 * time.Second):
	}
}

// TestChatNotifier_AdminWebhookUnsetDoesNotBlockFirstBlood — when no admin
// webhook URL is configured, first-blood still fires on the public webhook.
// Regression guard for the "if admin_webhook_url:" branch.
func TestChatNotifier_AdminWebhookUnsetDoesNotBlockFirstBlood(t *testing.T) {
	admin := testutil.AdminClient(t)
	sess := testutil.AdminSessionClient(t)
	ns := testutil.Namespace(t)

	publicMock := testutil.NewDiscordMock(t)
	t.Cleanup(func() { applyConfig(t, sess, "", "", false, false, "") })
	applyConfigFull(t, sess, "discord", publicMock.ContainerURL(), "",
		true, false, "{solver} solved {challenge} ({solve_num})", "")

	chal := testutil.CreateChallenge(t, admin, ns, "main", testutil.ChallengeStandard, testutil.ChallengeOpts{
		Flag: "flag{fb_no_admin}",
	})
	user := testutil.CreateUser(t, admin, ns, 1)
	uc := testutil.UserClient(t, user.Name, user.Password)
	if r := testutil.Submit(t, uc, chal.ID, "flag{fb_no_admin}"); r.Status != "correct" {
		t.Fatalf("submit: %s", r.Status)
	}

	got := publicMock.WaitFor(t, 5*time.Second)
	if _, ok := got.Body["embeds"].([]any); !ok {
		t.Errorf("expected first-blood embed even without admin webhook, got %v", got.Body)
	}
}
