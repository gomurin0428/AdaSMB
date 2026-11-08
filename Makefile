GPRBUILD ?= gprbuild
PYTHON ?= python3
ADAMUTANT ?= adamutant

MUTATION_BASE ?= origin/main

.PHONY: all build test integration transport-test unicode-test ntlm-test crypto-test aes-test cmac-test signing-test clock-test check stack-check clean example prove mutation mutation-diff

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

unicode-test:
	$(GPRBUILD) -p -P smb_tests.gpr unicode_probe.adb
	$(PYTHON) tests/unicode_conformance.py

ntlm-test:
	$(GPRBUILD) -p -P smb_tests.gpr ntlm_av_probe.adb
	$(PYTHON) tests/ntlm_av_conformance.py
	$(PYTHON) tests/ntlm_challenge_fields.py

crypto-test:
	$(GPRBUILD) -p -P smb_tests.gpr crypto_probe.adb
	$(PYTHON) tests/crypto_conformance.py

aes-test:
	$(GPRBUILD) -p -P smb_tests.gpr crypto_probe.adb
	$(PYTHON) tests/aes_conformance.py

cmac-test:
	$(GPRBUILD) -p -P smb_tests.gpr crypto_probe.adb
	$(PYTHON) tests/cmac_conformance.py

signing-test:
	$(GPRBUILD) -p -P smb_tests.gpr crypto_probe.adb
	$(PYTHON) tests/signing_conformance.py

clock-test:
	$(GPRBUILD) -p -P smb_tests.gpr clock_probe.adb
	$(PYTHON) tests/clock_conformance.py

transport-test:
	$(GPRBUILD) -p -P smb_tests.gpr transport_client.adb
	$(PYTHON) tests/transport_integration.py

check: stack-check
	$(GPRBUILD) -p -P smb.gpr -cargs:Ada -gnatwe
	$(GPRBUILD) -p -P smb_tests.gpr -cargs:Ada -gnatwe
	$(GPRBUILD) -p -P smb_example.gpr -cargs:Ada -gnatwe
	$(PYTHON) tests/check_sources.py

stack-check:
	$(GPRBUILD) -p -P smb.gpr --subdirs=stack-usage -cargs:Ada -fcallgraph-info=su
	$(PYTHON) tests/check_stack_usage.py

mutation:
	$(ADAMUTANT) run
	$(PYTHON) tests/mutation_survivors.py

mutation-diff:
	$(ADAMUTANT) run --since $(MUTATION_BASE)
	$(PYTHON) tests/mutation_survivors.py --fail

prove:
	@command -v gnatprove >/dev/null 2>&1 || { echo "gnatprove is required"; exit 127; }
	@gnatprove -P proof.gpr --mode=all --level=2 --proof=progressive --report=all \
		--checks-as-errors=on --prover=cvc5,z3 --timeout=120 -j4 \
		> gnatprove.out 2>&1; result=$$?; \
		cat gnatprove.out; exit $$result

clean:
	rm -rf build
