# Public source hygiene

This repository is public. Keep deployment runbooks, live test receipts, account
names/SIDs, tenant/device/application UUIDs, internal addresses, hostnames,
domains, personal details and organization-specific configuration outside Git.
Use clearly synthetic fixtures and reserved example domains in public examples.
Keep public project identifiers, standard protocol constants and required license
notices intact; they are interfaces or attribution, not deployment examples.

The identity experiment requires private generated build pins. Never commit its
generated Go deployment file, private mapping or signing key. Ordinary public
builds must keep that backend disabled when pins are absent. Describe test
behavior in public documentation without copying raw deployment evidence.
