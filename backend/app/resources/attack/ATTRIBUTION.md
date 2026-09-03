# ATT&CK Data Attribution

`enterprise-attack-slim.json` is derived from the MITRE ATT&CK® Enterprise
STIX 2.x dataset (https://github.com/mitre-attack/attack-stix-data),
reduced to the fields DetectionBench needs (technique ID, name, tactics,
platforms, reference URL, plus `revoked`/`deprecated` status and the
replacement ID from STIX `revoked-by` relationships) for deterministic,
offline technique-ID validation and lookup. Retired techniques are kept so
the linter can say "retired, replaced by X" instead of "unknown".

Copyright © MITRE Corporation. ATT&CK® is a registered trademark of The
MITRE Corporation. Used under the ATT&CK Terms of Use
(https://attack.mitre.org/resources/terms-of-use/). This project is not
affiliated with or endorsed by MITRE.

This file is regenerated offline from a fresh `enterprise-attack.json`
STIX bundle (link above). The 50MB+ source bundle and the reduction script
are kept out of the repo; the `attack_version` field inside the JSON records
which upstream release it was built from.
