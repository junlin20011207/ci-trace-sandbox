.PHONY: test serve benchmarks formal
serve:
	python app.py
test:
	bash run_all.sh
benchmarks:
	python experiments/paired_baselines.py && python experiments/latency.py
formal:
	python formal/exhaustive.py
