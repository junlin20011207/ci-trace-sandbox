"""V15 serialize signing-key revocation and authorization reservation.

V14 separately checked key_revoked before BEGIN IMMEDIATE: a revoked key
could still reserve one grant in the interval. This variant closes the gap.
"""
import hashlib
import time
from .approval_v14 import ApprovalLedger,verify_signed_grant,encode
from .provenance_guard import Denied,_require

class AtomicRevocationLedger(ApprovalLedger):
    def reserve(self,envelope,public_keys,authenticated_identity,*,now=None):
        _require(type(authenticated_identity) is str,'unauthenticated_recipient')
        rec=verify_signed_grant(envelope,public_keys,now=now)
        _require(rec['recipient']==authenticated_identity,'recipient_not_authorized')
        sha=hashlib.sha256(encode(rec)).hexdigest()
        t=time.time() if now is None else now
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            revoked=db.execute('SELECT 1 FROM revoked_keys WHERE key_id=?',
                              (envelope['key_id'],)).fetchone()
            _require(revoked is None,'approval_key_revoked')
            changed=db.execute("UPDATE grants SET state='uncertain' WHERE grant_id=?"
                   " AND record_sha=? AND recipient=? AND state='granted' AND expires>?",
                   (rec['grant_id'],sha,authenticated_identity,t)).rowcount
            _require(changed==1,'grant_not_redeemable')
            db.commit()
        return {'status':'uncertain_delivery','grant_id':rec['grant_id'],
                'sha256':rec['content_sha256'],'recipient':authenticated_identity}
