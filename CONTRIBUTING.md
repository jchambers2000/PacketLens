# Contributing to PacketLens

PacketLens emphasizes understandable evidence, conservative claims, local processing, and explicit user authorization.

## Contribution licensing

PacketLens is licensed under Apache License 2.0. Only submit material that you
have the right to contribute under that license. Do not submit employer-owned,
client-owned, copied, or otherwise restricted code or assets without the
necessary permission. Preserve applicable third-party notices and identify the
source and license of any permitted third-party material.

## Development setup

1. Use 64-bit Windows and Python 3.11 or newer.
2. Create a virtual environment: `py -m venv .venv`.
3. Install dependencies: `.venv\Scripts\python.exe -m pip install -r requirements.txt`.
4. Run tests: `.venv\Scripts\python.exe -m unittest discover -s tests -v`.

Npcap is not needed for offline development or automated tests. Tests must mock capture and discovery and must never scan or capture a real network.

## Change guidelines

- Keep analysis deterministic, evidence-linked, and transparent.
- Do not add stealth, exploitation, credential testing, port scanning, automatic capture/scanning, driver installation, or privilege escalation.
- Preserve offline analysis when Npcap is absent.
- Add focused tests and avoid private captures as fixtures.
- Use IANA documentation address ranges for public examples where private-subnet semantics are not required.
- Do not commit captures, reports, secrets, settings, build products, environments, or screenshots containing real network data.
- Keep public claims proportional to verified behavior.

Before proposing a change, run the complete tests, review
`PUBLICATION_MANIFEST_PROPOSED.txt`, and inspect the diff for addresses,
hostnames, credentials, machine paths, generated files, and license implications.
Security reports should follow [SECURITY.md](SECURITY.md), not a public issue.
