.PHONY: all data train eval test offline bench report study-selftest video demo clean
PY=python3
all: eval offline bench report
data:        ; $(PY) data/fetch_data.py && $(PY) scripts/01_prepare_data.py
train:       ; $(PY) scripts/02_train_sms.py && $(PY) scripts/03_train_url.py && $(PY) scripts/04_train_net.py && $(PY) scripts/make_demo_pcaps.py && $(PY) scripts/05_fit_fusion.py
eval:        ; $(PY) scripts/06_evaluate.py
test:        ; $(PY) -m pytest -q tests
offline:     ; $(PY) offline_proof/verify_offline.py
bench:       ; $(PY) bench/run_bench.py --label $${LABEL:-local} --iters 2000 && $(PY) bench/make_report.py
report:      ; $(PY) bench/make_report.py && $(PY) report/build_report.py
study-selftest: ; $(PY) study/build_scenarios.py && for i in 1 2 3 4 5 6; do $(PY) study/_selftest/ui_smoke_test.py $$i; done && $(PY) study/analyze_study.py --selftest
video:       ; $(PY) demo/video/build_video.py
demo:        ; $(PY) demo/app.py
