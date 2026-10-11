"""V13 durable authorization regression: replay, race, wrong identity, protected storage."""
import concurrent.futures
import hashlib
import secrets
import time
import pytest
from ci_trace.provenance_guard import Denied
from ci_trace.redeem_v13 import RedemptionLedger

SHA=hashlib.sha256(b'clean data').hexdigest()

@pytest.fixture
def ledger(tmp_path):
    folder=tmp_path/'issuer-only'
    folder.mkdir(mode=0o700)
    return RedemptionLedger(folder/'grants.sqlite')

def test_persistent_once_only_after_reopen(ledger):
    key=secrets.token_hex(32)
    ledger.issue(key,SHA,65534,time.time()+60)
    assert ledger.redeem(key,SHA,65534)['recipient_uid']==65534
    reopened=RedemptionLedger(ledger.path)
    with pytest.raises(Denied,match='grant_not_redeemable'):
        reopened.redeem(key,SHA,65534)

def test_wrong_identity_and_digest_do_not_consume_grant(ledger):
    key=secrets.token_hex(32);ledger.issue(key,SHA,65534,time.time()+60)
    for digest,uid in [('0'*64,65534),(SHA,1)]:
        with pytest.raises(Denied,match='grant_not_redeemable'):
            ledger.redeem(key,digest,uid)
    assert ledger.redeem(key,SHA,65534)

def test_expired_grant_fails_closed(ledger):
    key=secrets.token_hex(32);now=time.time()
    ledger.issue(key,SHA,65534,now+0.5,now=now)
    with pytest.raises(Denied,match='grant_not_redeemable'):
        ledger.redeem(key,SHA,65534,now=now+1)

def test_duplicate_grant_reissuance_forbidden(ledger):
    key=secrets.token_hex(32);ledger.issue(key,SHA,65534,time.time()+60)
    with pytest.raises(Denied,match='grant_id_already_issued'):
        ledger.issue(key,SHA,65534,time.time()+60)

def test_100_concurrent_claims_one_winner(ledger):
    key=secrets.token_hex(32);ledger.issue(key,SHA,65534,time.time()+60)
    def attempt(_):
        try:ledger.redeem(key,SHA,65534);return 1
        except Denied:return 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        assert sum(ex.map(attempt,range(100)))==1

def test_world_readable_ledger_folder_is_denied(tmp_path):
    folder=tmp_path/'public';folder.mkdir(mode=0o755)
    with pytest.raises(Denied,match='ledger_parent_permissive'):
        RedemptionLedger(folder/'db.sqlite')

def test_symlink_ledger_denied(tmp_path):
    folder=tmp_path/'safe';folder.mkdir(mode=0o700)
    other=tmp_path/'other';other.write_text('not a db')
    (folder/'link.sqlite').symlink_to(other)
    with pytest.raises(Denied,match='ledger_file_insecure'):
        RedemptionLedger(folder/'link.sqlite')
