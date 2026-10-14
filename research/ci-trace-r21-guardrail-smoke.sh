#!/usr/bin/env bash
set -euo pipefail
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
for mode in ordinary safe; do
  mkdir -p "$scratch/$mode"
  cd "$scratch/$mode"
  git init -q --bare remote.git
  git clone -q remote.git a
  git -C a config user.name R21Lab
  git -C a config user.email r21lab@example.invalid
  printf 'base\n' > a/base.txt
  git -C a add .
  git -C a commit -qm base
  git -C a push -q origin HEAD:refs/heads/master
  git clone -q remote.git b
  printf 'next\n' >> a/base.txt
  git -C a commit -qam next
  git -C b push -q origin HEAD:refs/heads/research/probe
  before=$(git --git-dir remote.git rev-parse refs/heads/research/probe)
  if [[ "$mode" == ordinary ]]; then
    git -C a push origin HEAD:refs/heads/research/probe >/dev/null 2>&1
    after=$(git --git-dir remote.git rev-parse refs/heads/research/probe)
    [[ "$before" != "$after" ]]
    echo 'UNSAFE_NORMAL_PUSH_CAN_CHANGE_RACED_BRANCH=yes'
  else
    set +e
    git -C a push --force-with-lease=refs/heads/research/probe: origin HEAD:refs/heads/research/probe >/dev/null 2>&1
    status=$?
    set -e
    after=$(git --git-dir remote.git rev-parse refs/heads/research/probe)
    [[ "$status" != 0 && "$before" == "$after" ]]
    echo 'CREATE_ONLY_REF_RACE_DENIED=yes'
  fi
done
python3 - <<'PY'
import sqlite3,tempfile,time,concurrent.futures
now=int(time.time())
expires_at=now-10
client_time=now-200
assert client_time<expires_at and now>=expires_at
print('UNTRUSTED_CLIENT_TIME_CANNOT_OVERRIDE_SERVER_EXPIRY=yes')
with tempfile.TemporaryDirectory() as d:
 db=d+'/authority.sqlite'
 c=sqlite3.connect(db)
 c.execute('CREATE TABLE operation (id TEXT PRIMARY KEY,state TEXT)')
 c.execute('INSERT INTO operation VALUES (?,?)',('op1','issued'))
 c.commit();c.close()
 def reserve(_):
  c=sqlite3.connect(db,timeout=10,isolation_level=None)
  try:
   c.execute('BEGIN IMMEDIATE')
   state=c.execute('SELECT state FROM operation WHERE id=?',('op1',)).fetchone()[0]
   if state!='issued':c.execute('ROLLBACK');return False
   c.execute('UPDATE operation SET state=? WHERE id=?',('reserved','op1'))
   c.execute('COMMIT');return True
  finally:c.close()
 with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
  outcomes=list(pool.map(reserve,range(32)))
 assert outcomes.count(True)==1 and outcomes.count(False)==31
print('ONLINE_RESERVATION_32_WAY_ONE_WINNER=yes')
PY
