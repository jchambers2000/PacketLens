"""PacketLens application entry point, including frozen-build diagnostics."""

import json
import sys
from pathlib import Path

from packetlens import __version__
from packetlens.runtime import is_frozen, write_startup_diagnostic


def main() -> int:
    try:
        from PySide6.QtWidgets import QApplication, QMessageBox
        from packetlens.app import PacketLensWindow
        from packetlens.live_capture import npcap_available

        app = QApplication.instance() or QApplication(sys.argv)
        app.setApplicationName("PacketLens")
        app.setOrganizationName("PacketLens")
        window = PacketLensWindow()
        if "--native-phase3-probe" in sys.argv:
            index = sys.argv.index("--native-phase3-probe")
            if index + 2 >= len(sys.argv):
                raise ValueError(
                    "--native-phase3-probe requires adapter text and an output path")
            if "--i-own-and-authorize-subnet-scan" not in sys.argv:
                raise ValueError(
                    "Native discovery validation requires explicit local-subnet authorization.")
            import threading
            import time
            from packetlens.analyzer import analyze_frames
            from packetlens.discovery import DiscoveryEngine
            from packetlens.live_capture import LiveCaptureEngine, enumerate_interfaces

            needle = sys.argv[index + 1].casefold()
            output = Path(sys.argv[index + 2])
            candidates = [
                item for item in enumerate_interfaces()
                if needle in item.description.casefold() and item.subnet
                and not item.is_virtual and item.is_available
            ]
            if len(candidates) != 1:
                raise ValueError("The authorized adapter selection was not unique.")
            interface = candidates[0]
            capture = LiveCaptureEngine(interface.identifier)
            discovery = DiscoveryEngine(interface, interface.subnet)
            capture_errors = []

            def run_capture():
                try:
                    capture.run()
                except Exception as exc:
                    capture_errors.append(str(exc))

            capture_thread = threading.Thread(
                target=run_capture, name="PacketLensPhase3Capture", daemon=True)
            started = time.monotonic()
            capture_thread.start()
            try:
                devices = discovery.run()
            finally:
                capture.stop()
                capture_thread.join(5.0)
            frames = capture.packets
            analysis = analyze_frames(frames, "frozen-native-validation.pcap") if frames else None
            result = {
                "version": __version__,
                "frozen": is_frozen(),
                "adapter_selection_unique": len(candidates) == 1,
                "authorized_private_subnet": bool(interface.subnet),
                "devices_discovered": len(devices),
                "captured_packets": len(frames),
                "capture_conversations": len(analysis.conversations) if analysis else 0,
                "capture_dns_activities": len(analysis.dns_activities) if analysis else 0,
                "discovery_handle_released": discovery._handle is None and discovery._api is None,
                "capture_handle_released": capture._handle is None and capture._api is None,
                "capture_thread_stopped": not capture_thread.is_alive(),
                "capture_errors": capture_errors,
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
            output.write_text(json.dumps(result, indent=2), encoding="utf-8")
            window.close()
            return 0 if (
                not capture_errors and not capture_thread.is_alive()
                and result["discovery_handle_released"]
                and result["capture_handle_released"]) else 1
        if "--regression-probe" in sys.argv:
            index = sys.argv.index("--regression-probe")
            if index + 2 >= len(sys.argv):
                raise ValueError("--regression-probe requires capture and output paths")
            from packetlens.analyzer import analyze_capture
            from packetlens.reports import build_html_report

            analysis = analyze_capture(sys.argv[index + 1])
            window._apply_analysis(analysis)
            app.processEvents()
            first_references = analysis.findings[0].references if analysis.findings else ()
            window.open_supporting_packets(first_references)
            app.processEvents()
            investigation_navigation = window.navigation.currentRow() == 1
            evidence_rows = window.traffic.proxy.rowCount()
            window.navigation.setCurrentRow(4)
            app.processEvents()
            report_html = build_html_report(analysis)
            result = {
                "version": __version__, "frozen": is_frozen(),
                "packets": len(analysis.packets),
                "conversations": len(analysis.conversations),
                "dns_queries": sum(item.query_count for item in analysis.dns_activities),
                "findings": len(analysis.findings),
                "traffic_rows": window.traffic.model.rowCount(),
                "conversation_rows": window.traffic.conversation_table.rowCount(),
                "dns_rows": window.traffic.dns_table.rowCount(),
                "finding_rows": window.findings.list.count(),
                "evidence_rows": evidence_rows,
                "investigation_navigation": investigation_navigation,
                "report_navigation": window.navigation.currentRow() == 4,
                "report_ready": window.reports.export_button.isEnabled(),
                "report_contains_counts": (
                    f"{len(analysis.conversations):,} conversations" in report_html
                    and f"{len(analysis.findings):,} security observations" in report_html
                ),
            }
            Path(sys.argv[index + 2]).write_text(
                json.dumps(result, indent=2), encoding="utf-8")
            window.close()
            return 0
        if "--packaging-probe" in sys.argv:
            index = sys.argv.index("--packaging-probe")
            if index + 1 >= len(sys.argv):
                raise ValueError("--packaging-probe requires an output path")
            app.processEvents()
            result = {
                "version": __version__, "frozen": is_frozen(),
                "page_count": window.pages.count(),
                "pages": [window.navigation.item(row).text()
                          for row in range(window.navigation.count())],
                "npcap_available": bool(npcap_available()),
            }
            Path(sys.argv[index + 1]).write_text(json.dumps(result, indent=2), encoding="utf-8")
            window.close()
            return 0
        window.show()
        return app.exec()
    except Exception as exc:
        diagnostic = write_startup_diagnostic(__version__, exc)
        try:
            message = "PacketLens could not start."
            if diagnostic:
                message += f"\n\nDiagnostic written to:\n{diagnostic}"
            if "QApplication" in locals() and QApplication.instance() is not None:
                QMessageBox.critical(None, "PacketLens startup error", message)
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
