#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
validation_dir="${ASTROGATE_VALIDATION_DIR:-validation}"
mkdir -p .local/core-classes "$validation_dir"
javac --release 21 -Xlint:all -d .local/core-classes backend/src/main/java/sbs/astrogate/mail/core/{Checks,Crypto,Totp,DnsRules}.java backend/core-tests/CoreChecks.java
java -ea -cp .local/core-classes CoreChecks | tee "$validation_dir/java-core-output.txt"
