"""A dashboard login may act on the ``<provider>:<user>`` rows Desktop stamps for it.

Desktop stamps its rows as ``<provider>:<user>`` (tui_gateway/session_transports.py), while a
forwarded dashboard actor carries ``authenticated_subject``'s ``auth:v1:[provider, "", user]``
form (gateway/session_identity.py). ``authorize_history`` compared the two byte for byte, so the
right logged-in user got ``permission_denied`` on rows it owned (#138950 review). The label maps
only for an issuer-less login — the label drops the issuer, so an issuer-bearing subject must not
claim one — and never to anything that itself reads as a subject.

As of the full-subject stamping change, Desktop stamps NEW rows with the complete
``auth:v1:[provider, issuer, user]`` subject directly (``authenticated_subject``) instead of the
lossy ``<provider>:<user>`` label — every real OIDC login carries a non-empty issuer, and the old
label dropped it unconditionally, so an issuer-bearing login could never satisfy an exact match
against its own row. ``_login_label`` above is UNCHANGED and still correct for its original,
narrower scope: an issuer-LESS login's row, stamped before this change or by an old client still
running the prior format. Rows stamped under the old lossy form by an issuer-BEARING login are
handled by a separate, bounded legacy fallback (``_legacy_transport_label`` /
``_legacy_label_eligible``) that only ever resolves a row provably created before this host's
recorded cutover to full-subject stamping — see the tests below this line.
"""

import pytest

from gateway.session_contract import Principal
from hermes_state import SessionDB
from hermes_state_mutation_binding import _login_label, authorize_history

LOGIN = 'auth:v1:["basic","","e2e"]'


def _actor(subject, tmp_path):
    return Principal(subject, str(tmp_path), frozenset({"session:read", "session:create"}), "native-http:x")


def _auth(db, subject, row_id):
    with db._read_ctx() as conn:
        return authorize_history(conn, _actor(subject, db.db_path.parent), row_id)


@pytest.fixture
def db(tmp_path):
    db = SessionDB(db_path=tmp_path / "state.db")
    yield db
    db.close()


def test_the_login_label_maps_for_an_issuer_less_login():
    assert _login_label(LOGIN) == "basic:e2e"


def test_a_desktop_labelled_row_takes_its_login(db):
    db.create_session("desktop-row", source="desktop", user_id="basic:e2e")
    assert _auth(db, LOGIN, "desktop-row") is True


def test_a_foreign_account_still_refused(db):
    db.create_session("mallory-row", source="desktop", user_id="basic:mallory")
    with pytest.raises(Exception) as raised:
        _auth(db, LOGIN, "mallory-row")
    assert getattr(raised.value, "reason", None) == "permission_denied"


def test_the_exact_subject_still_matches(db):
    db.create_session("subject-row", source="desktop", user_id=LOGIN)
    assert _auth(db, LOGIN, "subject-row") is True


@pytest.mark.parametrize("subject", [
    'auth:v1:["basic","https://idp.example","e2e"]',  # issuer-bearing: the label drops the issuer
    'auth:v1:["basic","",""]',                        # empty user
    'auth:v1:["basic","","  "]',                      # blank user
    'auth:v1:["ba:sic","","e2e"]',                    # a ':' in the provider would forge a third form
    'auth:v1:["","","e2e"]',                          # empty provider
    'auth:v1:["auth","","v1:[\\"x\\"]"]',             # label would read as a subject itself
    'auth:v1:"basic"',                                # non-list payload
    'uid:501',                                        # not a login subject at all
])
def test_labels_that_must_not_map(subject):
    assert _login_label(subject) is None


def test_an_issuer_bearing_login_cannot_touch_the_labelled_row(db):
    db.create_session("desktop-row", source="desktop", user_id="basic:e2e")
    with pytest.raises(Exception) as raised:
        _auth(db, 'auth:v1:["basic","https://idp.example","e2e"]', "desktop-row")
    assert getattr(raised.value, "reason", None) == "permission_denied"


def test_an_unowned_row_still_admits_any_local_actor(db):
    db.create_session("unowned-row", source="desktop")
    assert _auth(db, LOGIN, "unowned-row") is True


def test_one_parser_reads_the_login_subject_for_every_caller():
    """``authenticated_subject``'s format is parsed in one place: the control socket's
    forwarded-subject gate and the login label both use its checked result."""
    from gateway.control_socket import _structured_login_subject
    from gateway.session_identity import authenticated_subject, parse_authenticated_subject

    subject = authenticated_subject({'provider': 'basic', 'issuer': '', 'user_id': 'e2e'})
    assert parse_authenticated_subject(subject) == ('basic', '', 'e2e')
    for bad in ('uid:501', 'auth:v1:"basic"', 'auth:v1:[1,2,3]', 'auth:v1:["a","b"]', 'auth:v1:[', None, 7):
        assert parse_authenticated_subject(bad) is None
        assert _login_label(bad) is None
        if isinstance(bad, str):
            assert _structured_login_subject(bad) is False
    assert _structured_login_subject(subject) is True


def test_a_forwarded_bob_cannot_mutate_a_row_bound_to_alice(db):
    """F1 guard: a dashboard login ``bob`` (forwarded ``auth:v1:["basic","",bob]``) is refused on
    a Desktop row stamped ``basic:alice``, cannot claim it, and alice still owns it afterwards."""
    alice, bob = 'auth:v1:["basic","","alice"]', 'auth:v1:["basic","","bob"]'
    db.create_session("alice-row", source="desktop", user_id="basic:alice")
    with db._read_ctx() as conn:
        with pytest.raises(Exception) as raised:
            authorize_history(conn, _actor(bob, db.db_path.parent), "alice-row", claim=True)
        assert getattr(raised.value, "reason", None) == "permission_denied"
        assert authorize_history(conn, _actor(alice, db.db_path.parent), "alice-row") is True


# --- Legacy-cutover fallback: an issuer-bearing login reclaiming a pre-fix row -------------

OIDC_LOGIN = 'auth:v1:["self-hosted","https://idp.example","userid:123"]'


def _backdate(db, row_id, *, started_at):
    db._conn.execute("UPDATE sessions SET started_at=? WHERE id=?", (started_at, row_id))
    db._conn.commit()


def _set_cutover(db, *, when):
    from hermes_state_mutation_binding import _LEGACY_LABEL_CUTOVER_KEY
    db._conn.execute(
        "INSERT INTO state_meta(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (_LEGACY_LABEL_CUTOVER_KEY, str(when)))
    db._conn.commit()


def test_a_fresh_store_already_has_a_cutover_marker(db):
    """A brand-new store stamps the cutover at creation (alongside store_created_at_utc) so an
    import of previously-exported legacy session data into it still has a boundary to compare
    against — not just upgrading installs that pass through the version-gated migration chain."""
    from hermes_state_mutation_binding import _LEGACY_LABEL_CUTOVER_KEY
    with db._read_ctx() as conn:
        row = conn.execute(
            "SELECT value FROM state_meta WHERE key=?", (_LEGACY_LABEL_CUTOVER_KEY,)).fetchone()
    assert row is not None
    assert float(row[0]) > 0


def test_an_issuer_bearing_login_reclaims_a_pre_cutover_row_and_upgrades_it(db):
    """The actual bug this fallback fixes: a self-hosted OIDC login, which always carries an
    issuer, can reclaim a row stamped under the old lossy form before this host's cutover — and
    the row is upgraded in place so every later check hits the precise match directly."""
    db.create_session("oidc-row", source="desktop", user_id="self-hosted:userid:123")
    _backdate(db, "oidc-row", started_at=0.0)  # older than any real cutover timestamp
    with db._read_ctx() as conn:
        assert authorize_history(conn, _actor(OIDC_LOGIN, db.db_path.parent), "oidc-row", claim=True) is True
    with db._read_ctx() as conn:
        row = conn.execute("SELECT user_id FROM sessions WHERE id=?", ("oidc-row",)).fetchone()
    assert row["user_id"] == OIDC_LOGIN
    # Second touch now matches the FIRST branch (exact subject) directly — no fallback needed.
    assert _auth(db, OIDC_LOGIN, "oidc-row") is True


def test_a_pre_cutover_row_still_refuses_a_different_real_user(db):
    """The legacy fallback never widens who may claim a row — same provider, a genuinely
    different user, still refused even though the row predates the cutover."""
    mallory = 'auth:v1:["self-hosted","https://idp.example","userid:999"]'
    db.create_session("oidc-row", source="desktop", user_id="self-hosted:userid:123")
    _backdate(db, "oidc-row", started_at=0.0)
    with db._read_ctx() as conn:
        with pytest.raises(Exception) as raised:
            authorize_history(conn, _actor(mallory, db.db_path.parent), "oidc-row", claim=True)
        assert getattr(raised.value, "reason", None) == "permission_denied"


def test_a_post_cutover_row_never_gets_the_legacy_benefit(db):
    """Bounding by creation time, not just format: a row stamped with the old lossy label but
    created AFTER this host's cutover is never eligible for the fallback — current code never
    writes that format, so a mismatch here is a real foreign owner, not a legacy row. Proves the
    bound actually holds rather than merely never triggering by coincidence."""
    _set_cutover(db, when=1000.0)
    db.create_session("suspicious-row", source="desktop", user_id="self-hosted:userid:123")
    _backdate(db, "suspicious-row", started_at=2000.0)  # after the (test-set) cutover
    with db._read_ctx() as conn:
        with pytest.raises(Exception) as raised:
            authorize_history(conn, _actor(OIDC_LOGIN, db.db_path.parent), "suspicious-row", claim=True)
        assert getattr(raised.value, "reason", None) == "permission_denied"


def test_no_cutover_marker_means_the_fallback_refuses_rather_than_guesses(db):
    """A store somehow missing the marker (should not happen via the two writers above, but
    never assumed) fails closed: the fallback does not fire just because a row looks old."""
    from hermes_state_mutation_binding import _LEGACY_LABEL_CUTOVER_KEY
    db._conn.execute("DELETE FROM state_meta WHERE key=?", (_LEGACY_LABEL_CUTOVER_KEY,))
    db._conn.commit()
    db.create_session("oidc-row", source="desktop", user_id="self-hosted:userid:123")
    _backdate(db, "oidc-row", started_at=0.0)
    with db._read_ctx() as conn:
        with pytest.raises(Exception) as raised:
            authorize_history(conn, _actor(OIDC_LOGIN, db.db_path.parent), "oidc-row", claim=True)
        assert getattr(raised.value, "reason", None) == "permission_denied"
