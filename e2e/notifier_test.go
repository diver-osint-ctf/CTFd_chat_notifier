// Detailed tests for CTFd_chat_notifier:
// - first-blood vs subsequent-solve payload differences
// - notifier_solve_count cutoff
// - notification (announcement) → embed
// - {solver} {challenge} {solve_num} template placeholder expansion
// - notifier_type unset → no webhook calls
package e2e

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/diver-osint-ctf/ctfd-plugin-e2e/testutil"
)

// TestChatNotifier_FirstBloodEmbedFormat — first solve uses an embed payload
// with the canonical "First Blood!" title and the red colour code 15158332.
func TestChatNotifier_FirstBloodEmbedFormat(t *testing.T) {
	admin := testutil.AdminClient(t)
	sess := testutil.AdminSessionClient(t)
	ns := testutil.Namespace(t)

	mock := testutil.NewDiscordMock(t)
	t.Cleanup(func() { applyConfig(t, sess, "", "", false, false, "") })
	applyConfig(t, sess, "discord", mock.ContainerURL(), true, true,
		"{solver} solved {challenge} ({solve_num})")

	user := testutil.CreateUser(t, admin, ns, 1)
	chal := testutil.CreateChallenge(t, admin, ns, "main", testutil.ChallengeStandard, testutil.ChallengeOpts{
		Flag: "flag{first}",
	})
	uc := testutil.UserClient(t, user.Name, user.Password)
	if r := testutil.Submit(t, uc, chal.ID, "flag{first}"); r.Status != "correct" {
		t.Fatalf("submit: %s", r.Status)
	}

	got := mock.WaitFor(t, 5*time.Second)
	embeds, ok := got.Body["embeds"].([]any)
	if !ok || len(embeds) == 0 {
		t.Fatalf("first blood payload should include embeds[], got %v", got.Body)
	}
	first, _ := embeds[0].(map[string]any)
	title, _ := first["title"].(string)
	if !strings.Contains(title, "First Blood") {
		t.Errorf("expected First Blood title, got %q", title)
	}
	if c, _ := first["color"].(float64); int(c) != 15158332 {
		t.Errorf("expected color 15158332, got %v", first["color"])
	}
}

// TestChatNotifier_RegularSolveContent — second solve uses {"content": "..."}
// (no embeds). Drains the first-blood embed first, then asserts the shape of
// the second.
func TestChatNotifier_RegularSolveContent(t *testing.T) {
	admin := testutil.AdminClient(t)
	sess := testutil.AdminSessionClient(t)
	ns := testutil.Namespace(t)

	mock := testutil.NewDiscordMock(t)
	t.Cleanup(func() { applyConfig(t, sess, "", "", false, false, "") })
	applyConfig(t, sess, "discord", mock.ContainerURL(), true, true,
		"{solver} solved {challenge} ({solve_num})")

	chal := testutil.CreateChallenge(t, admin, ns, "main", testutil.ChallengeStandard, testutil.ChallengeOpts{
		Flag: "flag{rg}",
	})

	// First solver — first blood, drain.
	u1 := testutil.CreateUser(t, admin, ns, 1)
	uc1 := testutil.UserClient(t, u1.Name, u1.Password)
	_ = testutil.Submit(t, uc1, chal.ID, "flag{rg}")
	_ = mock.WaitFor(t, 5*time.Second)

	// Second solver — should be content-only.
	u2 := testutil.CreateUser(t, admin, ns, 2)
	uc2 := testutil.UserClient(t, u2.Name, u2.Password)
	_ = testutil.Submit(t, uc2, chal.ID, "flag{rg}")
	got := mock.WaitFor(t, 5*time.Second)

	if _, hasEmbeds := got.Body["embeds"]; hasEmbeds {
		t.Errorf("regular solve should not carry embeds, got %v", got.Body)
	}
	content, _ := got.Body["content"].(string)
	if content == "" {
		t.Errorf("regular solve should include content, got %v", got.Body)
	}
	// The "2nd" ordinal should appear since solve_num=2.
	if !strings.Contains(content, "2nd") {
		t.Errorf("expected ordinal '2nd' in content, got %q", content)
	}
}

// TestChatNotifier_SolveCountLimit — notifier_solve_count caps the number of
// notified solves per challenge. With cap=1 only the first solve is notified.
func TestChatNotifier_SolveCountLimit(t *testing.T) {
	admin := testutil.AdminClient(t)
	sess := testutil.AdminSessionClient(t)
	ns := testutil.Namespace(t)

	mock := testutil.NewDiscordMock(t)
	t.Cleanup(func() { applyConfig(t, sess, "", "", false, false, "") })
	applyConfigWithCount(t, sess, "discord", mock.ContainerURL(), true, true,
		"{solver} solved {challenge}", "1")

	chal := testutil.CreateChallenge(t, admin, ns, "main", testutil.ChallengeStandard, testutil.ChallengeOpts{
		Flag: "flag{cap}",
	})
	for i := 1; i <= 2; i++ {
		u := testutil.CreateUser(t, admin, ns, i)
		uc := testutil.UserClient(t, u.Name, u.Password)
		_ = testutil.Submit(t, uc, chal.ID, "flag{cap}")
	}
	// First-blood notified.
	_ = mock.WaitFor(t, 5*time.Second)
	// Second solve must be silent.
	select {
	case got := <-mock.Received:
		t.Errorf("expected no second notification (cap=1), got %v", got.Body)
	case <-time.After(2 * time.Second):
	}
}

// TestChatNotifier_NotifyMessageOnAnnouncement — admin POST notification
// fires the event_publish_decorator → notify_message → embed payload.
func TestChatNotifier_NotifyMessageOnAnnouncement(t *testing.T) {
	admin := testutil.AdminClient(t)
	sess := testutil.AdminSessionClient(t)

	mock := testutil.NewDiscordMock(t)
	t.Cleanup(func() { applyConfig(t, sess, "", "", false, false, "") })
	applyConfig(t, sess, "discord", mock.ContainerURL(), false, true, "")

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

	deadline := time.After(5 * time.Second)
	for {
		select {
		case got := <-mock.Received:
			embeds, _ := got.Body["embeds"].([]any)
			if len(embeds) > 0 {
				if e, ok := embeds[0].(map[string]any); ok {
					if title, _ := e["title"].(string); title == "Heads up" {
						return
					}
				}
			}
		case <-deadline:
			t.Fatalf("announcement embed not received")
		}
	}
}

// TestChatNotifier_TemplatePlaceholders — {solver}, {challenge}, {solve_num}
// are all expanded in either content or embed.description.
func TestChatNotifier_TemplatePlaceholders(t *testing.T) {
	admin := testutil.AdminClient(t)
	sess := testutil.AdminSessionClient(t)
	ns := testutil.Namespace(t)

	mock := testutil.NewDiscordMock(t)
	t.Cleanup(func() { applyConfig(t, sess, "", "", false, false, "") })
	applyConfig(t, sess, "discord", mock.ContainerURL(), true, false,
		"SOLVER={solver} CHAL={challenge} NTH={solve_num}")

	chal := testutil.CreateChallenge(t, admin, ns, "main", testutil.ChallengeStandard, testutil.ChallengeOpts{
		Flag: "flag{tpl}",
	})
	u := testutil.CreateUser(t, admin, ns, 1)
	uc := testutil.UserClient(t, u.Name, u.Password)
	_ = testutil.Submit(t, uc, chal.ID, "flag{tpl}")

	got := mock.WaitFor(t, 5*time.Second)
	desc := payloadDescription(got.Body)
	for _, marker := range []string{"SOLVER=", "CHAL=", "NTH="} {
		if !strings.Contains(desc, marker) {
			t.Errorf("missing template marker %q in payload: %q", marker, desc)
		}
	}
	// {solve_num} → "1st" via humanize.ordinalize
	if !strings.Contains(desc, "NTH=1st") {
		t.Errorf("expected NTH=1st (ordinalized), got %q", desc)
	}
}

// TestChatNotifier_NoTypeNoWebhook — notifier_type unset means no notifier
// is selected; even with sendSolves=true, no webhook is fired.
func TestChatNotifier_NoTypeNoWebhook(t *testing.T) {
	admin := testutil.AdminClient(t)
	sess := testutil.AdminSessionClient(t)
	ns := testutil.Namespace(t)

	mock := testutil.NewDiscordMock(t)
	t.Cleanup(func() { applyConfig(t, sess, "", "", false, false, "") })
	// notifier_type="" but sendSolves=true.
	applyConfig(t, sess, "", mock.ContainerURL(), true, true, "{solver} solved {challenge}")

	chal := testutil.CreateChallenge(t, admin, ns, "main", testutil.ChallengeStandard, testutil.ChallengeOpts{
		Flag: "flag{none}",
	})
	u := testutil.CreateUser(t, admin, ns, 1)
	uc := testutil.UserClient(t, u.Name, u.Password)
	if r := testutil.Submit(t, uc, chal.ID, "flag{none}"); r.HTTPStatus != http.StatusOK {
		t.Fatalf("submit: %d", r.HTTPStatus)
	}
	select {
	case got := <-mock.Received:
		t.Errorf("expected no webhook with notifier_type='', got %v", got.Body)
	case <-time.After(2 * time.Second):
	}
}

// applyConfigWithCount duplicates applyConfig but lets us pass a non-empty
// notifier_solve_count.
func applyConfigWithCount(t *testing.T, sess *testutil.Client, notifierType, webhookURL string, sendSolves, sendNotifications bool, msg, count string) {
	t.Helper()
	applyConfigFull(t, sess, notifierType, webhookURL, "", sendSolves, sendNotifications, msg, count)
}

func payloadDescription(body map[string]any) string {
	if c, ok := body["content"].(string); ok && c != "" {
		return c
	}
	if embeds, ok := body["embeds"].([]any); ok && len(embeds) > 0 {
		if m, ok := embeds[0].(map[string]any); ok {
			if d, ok := m["description"].(string); ok {
				return d
			}
		}
	}
	return ""
}
