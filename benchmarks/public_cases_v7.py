"""Retrospective security-advisory cases; original source snapshots from public Git history."""
import argparse,json
from pathlib import Path
from ci_trace.scanner_v7 import read,analyze
CASES=[
 ("GHSL-2026-204","spire_capture_vuln.yml","spire_apply_vuln.yml",True,"ARTIFACT_OVERLAY_IMPORT"),
 ("GHSL-2026-204 fixed snapshot","spire_capture_vuln.yml","spire_apply_fixed.yml",False,"ARTIFACT_OVERLAY_IMPORT"),
 ("GHSL-2026-225","attest_rebuild_vuln.yml","attest_commit_vuln.yml",True,"ARTIFACT_METADATA_REF_WRITE"),
 ("GHSL-2026-225 fixed snapshot","attest_rebuild_vuln.yml","attest_commit_fixed.yml",False,"ARTIFACT_METADATA_REF_WRITE"),
]
def evaluate(path):
    root=Path(path);result=[]
    for case,src,dst,expected,rule in CASES:
        found=analyze(src,read(root/src),dst,read(root/dst))
        actual=any(f["rule"]==rule for f in found)
        result.append({"case":case,"expected_disclosure_class":expected,
                       "detected":actual,"matched":expected==actual,
                       "rule":rule,"evidence":found})
    return result

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("dir",nargs="?",default="research_corpus")
    parser.add_argument("--assert-results",action="store_true")
    args=parser.parse_args();rows=evaluate(args.dir)
    summary={"evidence_type":"2 independently disclosed security advisories + 2 later fixed-control snapshots",
             "n":len(rows),"matched":sum(x["matched"] for x in rows),"cases":rows}
    print(json.dumps(summary,ensure_ascii=False,indent=2))
    return int(args.assert_results and not all(x["matched"] for x in rows))
if __name__=="__main__":raise SystemExit(main())
