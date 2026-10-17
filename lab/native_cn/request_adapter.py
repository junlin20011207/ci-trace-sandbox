"""OPTIONAL developer-authored CodeArts/Gitee Go bridge contract.
This is NOT a native official CodeArts/Gitee Go payload, nor proof that a
pipeline has an independently verifiable origin. It ONLY normalizes input.
The issuer independently preapproves exact subjects; adapter cannot approve.
"""
import hashlib,hmac,re,time,sqlite3
from pathlib import Path
from .crypto_sm import canonical,strict_json
ALLOWED={'platform','operation_id','source_commit_sha','workflow_identity','artifact_sm3',
         'recipient','target_repo','target_ref','created_at','nonce'}
REF=re.compile(r'^refs/heads/research/[A-Za-z0-9/_-]{8,120}$')
OP=re.compile(r'^[A-Za-z0-9_-]{8,60}$')
HEX40=re.compile(r'^[0-9a-f]{40}$'); HEX64=re.compile(r'^[0-9a-f]{64}$')

def verify_bridge_input(data,secret,signature_hex,now=None,nonce_store=None):
    """HMAC authenticates bridge sender ONLY; NOT approval or uneditable CI code."""
    if not isinstance(data,dict) or set(data)!=ALLOWED:return {'accepted':False,'reason':'FIELDS'}
    if not all(type(v)==str for k,v in data.items() if k!='created_at'):return {'accepted':False,'reason':'TYPE'}
    if type(data['created_at'])!=int:return {'accepted':False,'reason':'TIME_TYPE'}
    if data['platform'] not in ('CODEARTS','GITEE_GO'):return {'accepted':False,'reason':'UNKNOWN_PLATFORM'}
    if not OP.fullmatch(data['operation_id']) or not HEX40.fullmatch(data['source_commit_sha']):return {'accepted':False,'reason':'INVALID_ID'}
    if not HEX64.fullmatch(data['artifact_sm3']) or not REF.fullmatch(data['target_ref']) or '..' in data['target_ref']:return {'accepted':False,'reason':'INVALID_BINDING'}
    if data['target_repo']!='gitee.com/liljunlin/test' or data['recipient'] not in ('customer-A','customer-B'):return {'accepted':False,'reason':'UNSUPPORTED_TARGET'}
    if len(data['nonce'])<16 or len(data['nonce'])>80:return {'accepted':False,'reason':'NONCE'}
    server_now=int(time.time()) if now is None else now
    if abs(server_now-data['created_at'])>90:return {'accepted':False,'reason':'STALE_EVENT'}
    if not isinstance(secret,bytes) or len(secret)<32 or not isinstance(signature_hex,str):return {'accepted':False,'reason':'NO_VERIFIABLE_AUTHENTICITY'}
    digest=hmac.new(secret,canonical(data),'sha256').hexdigest()
    if not hmac.compare_digest(digest,signature_hex):return {'accepted':False,'reason':'HMAC_MISMATCH'}
    if nonce_store is not None and not nonce_store.try_consume(data['platform'],data['nonce'],server_now):
        return {'accepted':False,'reason':'REPLAYED_BRIDGE_NONCE'}
    return {'accepted':True,'adapter_nonce_dedup_enabled':nonce_store is not None,'classification':'UNTRUSTED_RELEASE_REQUEST_NOT_BUSINESS_APPROVAL',
            'requires_independent_policy':True,'request':data}

# Only the issuer-owned preapproval can supply missing security binding data.
# Never let a requester choose the target base SHA or policy itself.
def candidate_matches_preapproval(verified_bridge_result, issuer_owned_preapproval):
    if verified_bridge_result.get('accepted') is not True:return False
    data=verified_bridge_result.get('request',{})
    matches={'platform':'source_platform','operation_id':'operation_id',
             'source_commit_sha':'source_commit_sha','workflow_identity':'workflow_identity',
             'artifact_sm3':'artifact_sm3','recipient':'recipient',
             'target_repo':'target_repo','target_ref':'target_ref'}
    return all(data.get(source)==issuer_owned_preapproval.get(target) for source,target in matches.items())


class NonceStore:
    """Database-backed atomic HMAC bridge nonce deduplication. Not authorization."""
    def __init__(self,path):
        self.path=str(path)
        with sqlite3.connect(self.path) as c:
            c.execute('CREATE TABLE IF NOT EXISTS nonces (domain TEXT NOT NULL,nonce TEXT NOT NULL,seen_at INTEGER NOT NULL,PRIMARY KEY(domain,nonce))')
    def try_consume(self,domain,nonce,now):
        with sqlite3.connect(self.path,timeout=10,isolation_level=None) as c:
            c.execute('BEGIN IMMEDIATE')
            try:
                c.execute('DELETE FROM nonces WHERE seen_at<?',(now-3600,))
                c.execute('INSERT INTO nonces(domain,nonce,seen_at) VALUES (?,?,?)',(domain,nonce,now))
                c.commit();return True
            except sqlite3.IntegrityError:
                c.rollback();return False
