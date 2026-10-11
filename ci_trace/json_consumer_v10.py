"""Atomic signed-provenance-to-data handoff within one trusted process.

Only inert scalar JSON. Does not authorize code execution, branch selection or
publishing; signer, keys, policy, runner and this function must be trusted.
"""
import json
import re
import shutil
from .provenance_guard import Denied, _require
from .signed_snapshot_v10 import verify_signed_snapshot_release
from .verified_reader_v10 import read_verified_member

SAFE_KEY = re.compile(r'[a-z][a-z0-9_]{0,63}\Z')
MAX_JSON_BYTES = 1024 * 1024
TYPES = {'string': str, 'integer': int, 'boolean': bool}
RESERVED = {'head_ref', 'head-ref', 'git_ref', 'checkout_ref', 'target_branch', 'branch'}

def parse_scalar_json(data, schema):
    _require(isinstance(schema, dict) and schema and all(
        isinstance(k, str) and SAFE_KEY.fullmatch(k) and k not in RESERVED
        and v in TYPES for k,v in schema.items()), 'invalid_scalar_schema')
    _require(isinstance(data, bytes) and len(data) <= MAX_JSON_BYTES, 'json_size_limit')
    def unique_pairs(pairs):
        result={}
        for key,value in pairs:
            _require(key not in result, 'duplicate_json_key')
            result[key]=value
        return result
    def forbidden_constant(value):
        raise Denied('nonfinite_json_constant')
    try:
        obj=json.loads(data.decode('utf-8'), object_pairs_hook=unique_pairs,
                       parse_constant=forbidden_constant)
    except (UnicodeError,json.JSONDecodeError) as exc:
        raise Denied('invalid_json_payload') from exc
    _require(isinstance(obj,dict) and set(obj)==set(schema), 'json_schema_mismatch')
    for key,kind in schema.items():
        _require(type(obj[key]) is TYPES[kind], 'json_scalar_type_mismatch')
        if kind=='string':
            _require(len(obj[key]) <= 4096, 'json_string_too_long')
    return obj

def consume_signed_json(archive,event,artifact,policy,package,keys,
                        output_root,workspace,member,schema,now=None):
    record=verify_signed_snapshot_release(archive,event,artifact,policy,package,
                                          keys,output_root,workspace,now=now)
    try:
        data=read_verified_member(record,member,max_bytes=MAX_JSON_BYTES)
        parsed=parse_scalar_json(data,schema)
        return {'status':'approved','data':parsed,
                'source_commit_from_signed_approval':record['approval_binding']['authorized_commit_sha'],
                'source_run':record['run_id'],'artifact_id':record['artifact_id'],
                'payload_from_exact_snapshot':True,
                'safe_to_execute_or_publish':False}
    finally:
        shutil.rmtree(record['release_dir'])
