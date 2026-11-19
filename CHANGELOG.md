# Changelog

PacketLens has not yet published a public GitHub release.

## 0.8.4 - Licensing-compliance candidate

- Applied Apache License 2.0 to authorized original PacketLens source and prepared a source-only publication allowlist.
- Added a curated, versioned third-party license bundle to the onedir package.
- Added Qt/PySide source-availability and library-replacement documentation.
- Added final compliance and release-readiness records without selecting a PacketLens license.
- Re-audited the frozen dependency set, external Npcap boundary, and proposed publication manifest.

## 0.8.3 - Scapy-free technical candidate

- Removed Scapy from production imports, runtime requirements, tests, and PyInstaller configuration.
- Replaced generated test packets with independently constructed dpkt/standard-library fixtures.
- Preserved dpkt offline analysis and native Npcap capture, saving, interface enumeration, and ARP discovery.
- Added isolated no-Scapy environment, frozen-archive, regression-capture, and distribution verification.

## 0.8.1 - Dependency cleanup candidate

- Replaced broad Scapy aggregator imports with explicit runtime modules.
- Restricted the Windows package to the audited Qt Widgets runtime and common image plugins.
- Removed the unused Qt Virtual Keyboard, QML/Quick, PDF, Qt Network, and optional platform-plugin stacks from the test distribution.
- Added packaging validation for required and excluded Qt components.

## 0.8.0 - Release candidate

- Prepared a sanitized, allowlisted source repository for public review.
- Added installation, usage, privacy, limitations, security, contribution, and dependency-license documentation.
- Added deterministic synthetic screenshots and publication-integrity tests.
- Pinned tested runtime and build dependencies.
- Added version-consistency and public-manifest validation.
- Built a fresh Windows x64 portable release candidate with content validation.

## 0.7.0

- Added maintained PyInstaller onedir/windowed packaging, frozen startup probing, portable ZIP creation, and SHA-256 generation.
- Added local failure diagnostics and distribution content validation.

## 0.6.0

- Added traffic filters, packet explanations, technical evidence, display scaling, and usability refinements.

## 0.5.x

- Added conversation and DNS investigations, direction-aware findings, evidence previews, and the Findings master-detail interface.
- Refined Network and device investigation workflows.

## 0.2.0 - 0.4.0

- Added bounded live capture, PCAP saving, explicit local ARP discovery, interface/subnet safeguards, and device navigation.

## 0.1.0

- Established the desktop application, offline analysis, findings, and local HTML reports.
