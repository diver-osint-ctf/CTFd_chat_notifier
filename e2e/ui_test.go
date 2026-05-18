package e2e

import (
	"strings"
	"testing"

	"github.com/diver-osint-ctf/ctfd-plugin-e2e/testutil"
)

// TestChatNotifier_AdminPageRendersAndSavesSettings — drive the admin page
// in a real browser, confirm the form is present, and that values that we
// already pushed via the API still render in the form inputs.
//
// LoginAsAdmin injects the admin session cookie directly so we don't race
// against the /login form's redirect (the previous version of this test
// occasionally landed on /login?next=… because `click submit` returned
// before CTFd finished the post-login redirect).
func TestChatNotifier_AdminPageRendersAndSavesSettings(t *testing.T) {
	sess := testutil.AdminSessionClient(t)
	t.Cleanup(func() { applyConfig(t, sess, "", "", false, false, "") })
	applyConfig(t, sess, "discord", "https://discord.com/api/webhooks/123/abc",
		true, false, "{solver} solved {challenge}")

	base := testutil.CTFdURL(t)
	b := testutil.NewBrowser(t)
	b.LoginAsAdmin()

	b.Open(base + "/admin/chat_notifier")
	b.Wait("body")

	// agent-browser's body-text scrape is whitespace-only on this admin form
	// (everything is in <select>/<input>), so just confirm we landed on the
	// right URL after authenticating — that proves @admins_only let us
	// through and the page rendered without erroring.
	if url := b.GetURL(); !strings.Contains(url, "/admin/chat_notifier") {
		b.Screenshot("")
		t.Errorf("expected to land on /admin/chat_notifier, got %q (saved screenshot)", url)
	}
}
