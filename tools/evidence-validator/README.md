# Evidence validator

**SOURCE_SUPPORTED:** this is a wrapper guide for the repository's offline metadata validator. It does not open USB, run a modem query, contact a vendor or authenticate withheld raw measurements.

From the repository root, with the development environment active:

```sh
python3 scripts/evidence_validator.py
```

Review [evidence-level definitions](../../docs/evidence-levels.md) and the [sanitized summaries](../../evidence/README.md). The validator checks the structures and bounded invariants implemented in the script; its success must not be described as independent physical verification. Source hashes identify withheld evidence but cannot reproduce missing raw inputs.

The measured 29-service list retains unknown numeric service IDs. The USB summary excludes the actual serial and keeps unknown roles. WDA state remains distinct from physical packet format. No validation result may automatically set the project's final verdict or end-to-end 5G status.

Use the actual script output for the current check set and failures. Do not replace absent measurement fields with zeros or synthetic data merely to satisfy a schema.
