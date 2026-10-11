from ci_trace.scanner import scan

PRODUCER = """name: PR Build
on: [pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@v4
"""
CONSUMER = """name: Publish
on:
  workflow_run:
    workflows: [PR Build]
    types: [completed]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
      - run: bash ./dist/release.sh
"""

def check(tmp_path, producer=PRODUCER, consumer=CONSUMER):
    (tmp_path / "pr.yml").write_text(producer)
    (tmp_path / "publish.yml").write_text(consumer)
    return scan(tmp_path)

def test_path(tmp_path):
    assert check(tmp_path)["findings"][0]["severity"] == "review_required"

def test_no_download(tmp_path):
    assert not check(tmp_path, consumer=CONSUMER.replace("download-artifact", "checkout"))["findings"]

def test_wrong_name(tmp_path):
    assert not check(tmp_path, consumer=CONSUMER.replace("[PR Build]", "[Other]"))["findings"]

def test_no_upload(tmp_path):
    assert not check(tmp_path, producer=PRODUCER.replace("upload-artifact", "checkout"))["findings"]

def test_no_execution(tmp_path):
    r = check(tmp_path, consumer=CONSUMER.replace("bash ./dist/release.sh", "echo done"))
    assert r["findings"][0]["severity"] == "informational"

def test_gh_download(tmp_path):
    r = check(tmp_path, consumer=CONSUMER.replace("uses: actions/download-artifact@v4", "run: gh run download 123"))
    assert len(r["findings"]) == 1

def test_invalid_yaml(tmp_path):
    (tmp_path / "bad.yml").write_text("on: [broken")
    assert len(scan(tmp_path)["parse_errors"]) == 1

def test_pull_request_target(tmp_path):
    assert len(check(tmp_path, producer=PRODUCER.replace("pull_request", "pull_request_target"))["findings"]) == 1

def test_dispatch(tmp_path):
    assert not check(tmp_path, producer=PRODUCER.replace("pull_request", "workflow_dispatch"))["findings"]

def test_on_yaml_bool(tmp_path):
    assert check(tmp_path)["workflow_count"] == 2

def test_empty_dir(tmp_path):
    assert scan(tmp_path)["findings"] == []

def test_download_after_execution(tmp_path):
    consumer = CONSUMER.replace(
        "      - uses: actions/download-artifact@v4\n      - run: bash ./dist/release.sh",
        "      - run: bash ./dist/release.sh\n      - uses: actions/download-artifact@v4")
    assert check(tmp_path, consumer=consumer)["findings"][0]["severity"] == "informational"

def test_disjoint_paths(tmp_path):
    consumer = CONSUMER.replace("uses: actions/download-artifact@v4",
        "uses: actions/download-artifact@v4\n        with:\n          path: staging")
    assert check(tmp_path, consumer=consumer)["findings"][0]["severity"] == "informational"

def test_overlapping_paths(tmp_path):
    consumer = CONSUMER.replace("uses: actions/download-artifact@v4",
        "uses: actions/download-artifact@v4\n        with:\n          path: dist")
    finding = check(tmp_path, consumer=consumer)["findings"][0]
    assert finding["severity"] == "review_required"
    assert finding["evidence"]["candidate_edges"][0]["download_path"] == "dist"

def test_different_jobs(tmp_path):
    consumer = CONSUMER.replace("      - run: bash ./dist/release.sh",
        "  secondary:\n    runs-on: ubuntu-latest\n    steps:\n      - run: bash ./dist/release.sh")
    assert check(tmp_path, consumer=consumer)["findings"][0]["severity"] == "informational"

def test_dynamic_download_path(tmp_path):
    consumer = CONSUMER.replace("uses: actions/download-artifact@v4",
        "uses: actions/download-artifact@v4\n        with:\n          path: ${{ env.TARGET }}")
    assert check(tmp_path, consumer=consumer)["findings"][0]["severity"] == "informational"

def test_parent_path_is_unknown(tmp_path):
    consumer = CONSUMER.replace("uses: actions/download-artifact@v4",
        "uses: actions/download-artifact@v4\n        with:\n          path: ../dist")
    assert check(tmp_path, consumer=consumer)["findings"][0]["severity"] == "informational"

def test_path_prefix_not_substring(tmp_path):
    consumer = CONSUMER.replace("uses: actions/download-artifact@v4",
        "uses: actions/download-artifact@v4\n        with:\n          path: di")
    assert check(tmp_path, consumer=consumer)["findings"][0]["severity"] == "informational"

def test_gh_download_path_unknown(tmp_path):
    consumer = CONSUMER.replace("uses: actions/download-artifact@v4",
        "run: gh run download 123")
    assert check(tmp_path, consumer=consumer)["findings"][0]["severity"] == "informational"
