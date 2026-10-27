GPRBUILD ?= gprbuild
PYTHON ?= python3

.PHONY: all build test integration transport-test check clean example prove

all: build

build:
	$(GPRBUILD) -p -P smb.gpr

example:
	$(GPRBUILD) -p -P smb_example.gpr

test:
	$(GPRBUILD) -p -P smb_tests.gpr
	./build/bin/test_suite

integration: test
	$(PYTHON) tests/transport_integration.py
	$(PYTHON) tests/samba_integration.py

transport-test:
	$(GPRBUILD) -p -P smb_tests.gpr transport_client.adb
	$(PYTHON) tests/transport_integration.py

check:
	$(GPRBUILD) -p -P smb.gpr -cargs:Ada -gnatwe
	$(GPRBUILD) -p -P smb_tests.gpr -cargs:Ada -gnatwe
	$(GPRBUILD) -p -P smb_example.gpr -cargs:Ada -gnatwe
	$(PYTHON) tests/check_sources.py

prove:
	@command -v gnatprove >/dev/null 2>&1 || { echo "gnatprove is required"; exit 127; }
	@gnatprove -P proof.gpr --mode=all --level=2 --report=all \
		--checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4 \
		> gnatprove.out 2>&1; result=$$?; \
		cat gnatprove.out; exit $$result

clean:
	rm -rf build
