// Coverage for the geo-challenge solve notification path.
//
// _geo_chal_solve_decorator (src/decorators.py) wraps geo_challenge_class.solve
// as a classmethod, distinct from the BaseChallenge.solve wrapper that handles
// normal challenges. None of the other tests exercise this branch, so a geo
// solve regressing silently would slip through.
package e2e

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/diver-osint-ctf/ctfd-plugin-e2e/testutil"
)

const (
	tokyoLat = 35.6586
	tokyoLon = 139.7454
)

// submitGeoCoords mirrors geo_challenges' submission shape: lat/lon JSON body
// against /api/v1/challenges/attempt (the geo plugin reads them out of
// request.get_json()).
func submitGeoCoords(t *testing.T, c *testutil.Client, challengeID int, lat, lon float64) testutil.SubmitResult {
	t.Helper()
	body := map[string]any{
		"challenge_id": challengeID,
		"latitude":     lat,
		"longitude":    lon,
	}
	var resp struct {
		Success bool                  `json:"success"`
		Data    testutil.SubmitResult `json:"data"`
	}
	r, err := c.PostJSON("/api/v1/challenges/attempt", body, &resp)
	if err != nil {
		t.Fatalf("submit geo coords: %v", err)
	}
	out := resp.Data
	out.HTTPStatus = r.StatusCode
	return out
}

// TestChatNotifier_GeoChallengeFirstBlood — a first solve on a geo challenge
// must reach the webhook via the _geo_chal_solve_decorator path, with the same
// embed shape as a standard first blood.
func TestChatNotifier_GeoChallengeFirstBlood(t *testing.T) {
	admin := testutil.AdminClient(t)
	sess := testutil.AdminSessionClient(t)
	ns := testutil.Namespace(t)

	mock := testutil.NewDiscordMock(t)
	t.Cleanup(func() { applyConfig(t, sess, "", "", false, false, "") })
	applyConfig(t, sess, "discord", mock.ContainerURL(), true, false,
		"{solver} solved {challenge} ({solve_num})")

	chal := testutil.CreateChallenge(t, admin, ns, "geo", testutil.ChallengeGeo, testutil.ChallengeOpts{
		Value: 100,
		Extra: map[string]any{
			"latitude":         tokyoLat,
			"longitude":        tokyoLon,
			"tolerance_radius": 500,
		},
	})

	user := testutil.CreateUser(t, admin, ns, 1)
	uc := testutil.UserClient(t, user.Name, user.Password)
	r := submitGeoCoords(t, uc, chal.ID, tokyoLat, tokyoLon)
	if r.HTTPStatus != http.StatusOK || r.Status != "correct" {
		t.Fatalf("geo submit: expected 200/correct, got %d/%s (%s)", r.HTTPStatus, r.Status, r.Message)
	}

	got := mock.WaitFor(t, 5*time.Second)
	embeds, ok := got.Body["embeds"].([]any)
	if !ok || len(embeds) == 0 {
		t.Fatalf("expected first-blood embed for geo solve, got %v", got.Body)
	}
	first, _ := embeds[0].(map[string]any)
	if title, _ := first["title"].(string); !strings.Contains(title, "First Blood") {
		t.Errorf("geo first blood: expected First Blood title, got %q", title)
	}
	if desc, _ := first["description"].(string); !strings.Contains(desc, user.Name) || !strings.Contains(desc, chal.Name) {
		t.Errorf("geo first blood description should include solver and challenge name, got %q", desc)
	}
}

// TestChatNotifier_GeoChallengeRegularSolveContent — second geo solve goes
// through the same content-payload path as a standard regular solve, proving
// the geo decorator isn't accidentally forcing the first-blood branch.
func TestChatNotifier_GeoChallengeRegularSolveContent(t *testing.T) {
	admin := testutil.AdminClient(t)
	sess := testutil.AdminSessionClient(t)
	ns := testutil.Namespace(t)

	mock := testutil.NewDiscordMock(t)
	t.Cleanup(func() { applyConfig(t, sess, "", "", false, false, "") })
	applyConfig(t, sess, "discord", mock.ContainerURL(), true, false,
		"{solver} solved {challenge} ({solve_num})")

	chal := testutil.CreateChallenge(t, admin, ns, "geo", testutil.ChallengeGeo, testutil.ChallengeOpts{
		Value: 100,
		Extra: map[string]any{
			"latitude":         tokyoLat,
			"longitude":        tokyoLon,
			"tolerance_radius": 500,
		},
	})

	u1 := testutil.CreateUser(t, admin, ns, 1)
	_ = submitGeoCoords(t, testutil.UserClient(t, u1.Name, u1.Password), chal.ID, tokyoLat, tokyoLon)
	_ = mock.WaitFor(t, 5*time.Second) // drain first blood

	u2 := testutil.CreateUser(t, admin, ns, 2)
	_ = submitGeoCoords(t, testutil.UserClient(t, u2.Name, u2.Password), chal.ID, tokyoLat, tokyoLon)
	got := mock.WaitFor(t, 5*time.Second)

	if _, hasEmbeds := got.Body["embeds"]; hasEmbeds {
		t.Errorf("geo regular solve should not carry embeds, got %v", got.Body)
	}
	if c, _ := got.Body["content"].(string); !strings.Contains(c, "2nd") {
		t.Errorf("expected ordinal '2nd' in content, got %q", c)
	}
}
