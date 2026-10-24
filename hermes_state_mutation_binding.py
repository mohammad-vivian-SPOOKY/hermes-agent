"""Control-only ownership for unbound legacy history; never an execution policy."""
import json
from hermes_state_runtime import RuntimeStoreError

BINDING_PREFIX = 'gateway.history_control.v1.'


def _history_sources():
    """Local surfaces whose unrouted rows are owner history: every source the native resume adopts
    (``LEGACY_LOCAL_SOURCES``: old ``desktop`` chats and ``oneshot``/``tool`` CLI runs too) plus imports.
    A row resume can adopt must also take a sidebar edit (pin/archive/hide/rename)."""
    from hermes_state_local_migration import LEGACY_LOCAL_SOURCES
    return LEGACY_LOCAL_SOURCES | {'import'}


def _owner_user(row):
    """The row's owner identity; main's Desktop Nous-account label is not one (see validate_legacy_row)."""
    from hermes_state_local_migration import legacy_account_label
    return None if legacy_account_label(dict(row)) else row['user_id']


def _login_label(subject):
    """The ``<provider>:<user>`` label Desktop stamps on its rows (tui_gateway/session_transports.py) when it
    names exactly the dashboard subject ``auth:v1:[provider, "", user]`` (gateway/session_identity.py).
    Only an issuer-less login maps: the label drops the issuer, so an issuer-bearing subject must not claim it."""
    from gateway.session_identity import parse_authenticated_subject
    parts = parse_authenticated_subject(subject)
    if parts is None:
        return None
    provider, issuer, user = parts
    if issuer or ':' in provider or not provider.strip() or not user.strip():
        return None
    label = f'{provider.strip()}:{user.strip()}'
    # Never yield something that reads as a subject itself (a provider named ``auth`` + user ``v1:[...]``).
    return None if label.startswith('auth:') else label


_LEGACY_LABEL_CUTOVER_KEY = 'legacy_login_label_cutover'


def _legacy_transport_label(subject):
    """What ``tui_gateway/session_transports.py::_transport_auth_user_id`` stamped on a row
    BEFORE it carried the full subject: ``<provider>:<user>``, issuer dropped regardless of
    whether one is present. Unlike ``_login_label`` (which deliberately still refuses an
    issuer-bearing subject — that refusal protects every row stamped under the CURRENT,
    full-subject scheme), this exists only to let a genuine owner's first post-upgrade touch
    reclaim a row stamped under the OLD scheme, where the issuer was never captured at all and
    provider+user was genuinely the only identity information stored. Never used on its own as
    a permanent equivalence — see ``_legacy_label_eligible`` for the bound that keeps it from
    reopening once a provider is backed by more than one issuer."""
    from gateway.session_identity import parse_authenticated_subject
    parts = parse_authenticated_subject(subject)
    if parts is None:
        return None
    provider, _issuer, user = parts
    if ':' in provider or not provider.strip() or not user.strip():
        return None
    label = f'{provider.strip()}:{user.strip()}'
    return None if label.startswith('auth:') else label


def _legacy_label_cutover(conn):
    """Unix timestamp this install's ``state.db`` crossed the schema version that switched row
    stamping from the lossy ``<provider>:<user>`` form to the full subject (written once, by the
    schema migration, the first time that version is reached — see hermes_state_schema.py).
    ``None`` on a store that hasn't crossed it yet (migration chain order means this can only
    happen mid-migration-chain on first open, not in steady state) or one that somehow lacks the
    marker — either way, the legacy fallback below must refuse rather than guess."""
    row = conn.execute(
        "SELECT value FROM state_meta WHERE key=?", (_LEGACY_LABEL_CUTOVER_KEY,)).fetchone()
    try:
        return float(row[0]) if row is not None else None
    except (TypeError, ValueError):
        return None


def _legacy_label_eligible(conn, row):
    """Whether *row* may still be matched via ``_legacy_transport_label`` instead of requiring an
    exact full-subject match. Bounded to rows that demonstrably predate this host's cutover to
    full-subject stamping — a row created after the cutover can only have been stamped by the
    CURRENT code, which never writes the lossy form, so treating it as legacy-eligible would mean
    guessing an equivalence that was never structurally guaranteed (the exact gap that let one
    provider name collide across two different issuers). A row with no ``started_at`` (should not
    happen for a real row, but never assumed) is treated as NOT eligible — fail closed, not open."""
    cutover = _legacy_label_cutover(conn)
    started_at = row['started_at'] if 'started_at' in row.keys() else None
    return cutover is not None and isinstance(started_at, (int, float)) and started_at < cutover


def import_history_control(conn, actor, session_ids):
    binding = json.dumps([actor.profile_id, actor.subject], separators=(',', ':'))
    for sid in session_ids:
        if conn.execute('SELECT 1 FROM sessions WHERE id=?', (sid,)).fetchone() is None:
            conn.execute('INSERT INTO state_meta(key,value) VALUES(?,?)', (BINDING_PREFIX + sid, binding))


def authorize_history(conn, actor, session_id, *, claim=False):
    row = conn.execute('SELECT * FROM sessions WHERE id=?', (session_id,)).fetchone()
    if row is None:
        return False
    # Import intentionally strips routes. Never reinterpret a cold native/API
    # transcript as imported history, even if stale import metadata exists.
    if row['session_key'] or row['chat_id'] or row['origin_json']:
        return False
    key = BINDING_PREFIX + session_id
    binding = json.dumps([actor.profile_id, actor.subject], separators=(',', ':'))
    saved = conn.execute('SELECT value FROM state_meta WHERE key=?', (key,)).fetchone()
    if saved is not None:
        if saved[0] != binding:
            raise RuntimeStoreError('permission_denied')
        return True
    if row['source'] not in _history_sources():
        return False
    owner = _owner_user(row)
    legacy_upgrade = False
    if owner and owner not in (actor.subject, _login_label(actor.subject)):
        # The exact/current-scheme match failed. A row stamped before this host's cutover to
        # full-subject stamping may still carry the old, issuer-dropped `<provider>:<user>`
        # form — the ONLY case that fallback may resolve, bounded by _legacy_label_eligible so
        # it can never reopen once a provider is backed by more than one issuer (see that
        # function's docstring). Anything else (a genuinely foreign owner, or a row created
        # after the cutover that still mismatches) is refused exactly as before.
        if _legacy_label_eligible(conn, row) and owner == _legacy_transport_label(actor.subject):
            legacy_upgrade = True
        else:
            raise RuntimeStoreError('permission_denied')
    if 'session:create' not in actor.capabilities:
        raise RuntimeStoreError('permission_denied')
    if claim:
        if legacy_upgrade:
            # First touch by the genuine owner since this host crossed the full-subject cutover:
            # upgrade the row in place so every later comparison hits the precise, issuer-bearing
            # match directly and this fallback is never consulted for it again.
            conn.execute('UPDATE sessions SET user_id=? WHERE id=?', (actor.subject, session_id))
        conn.execute('INSERT INTO state_meta(key,value) VALUES(?,?)', (key, binding))
    return True


def history_binding(conn, session_id):
    saved = conn.execute('SELECT value FROM state_meta WHERE key=?', (BINDING_PREFIX + session_id,)).fetchone()
    return saved[0] if saved else None


def same_history_owner(conn, anchor_id, session_id):
    """Whether chain member ``session_id`` is history the authorizer of ``anchor_id`` controls.

    A real compression continuation copies its parent's route columns, so a routed member must
    carry the anchor's exact (user_id, session_key, chat_id). A routeless member needs the
    anchor's exact import binding; unbound, it must also pass :func:`authorize_history`'s local
    rule (local source, no foreign user_id) — e.g. the pre-adoption ancestors of an adopted
    legacy CLI conversation. A bound (imported) anchor therefore never reaches unbound rows.
    """
    columns = 'SELECT source,user_id,session_key,chat_id,origin_json FROM sessions WHERE id=?'
    anchor, row = (conn.execute(columns, (sid,)).fetchone() for sid in (anchor_id, session_id))
    if anchor is None or row is None:
        return False
    if row['session_key'] or row['chat_id'] or row['origin_json']:
        return tuple(row)[1:4] == tuple(anchor)[1:4]
    binding = history_binding(conn, session_id)
    if binding != history_binding(conn, anchor_id):
        return False
    return binding is not None or (
        row['source'] in _history_sources() and _owner_user(row) in (None, '', anchor['user_id']))
