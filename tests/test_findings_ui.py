import os
import unittest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication, QLabel

from packetlens.models import Finding
from packetlens.pages.findings import FindingsPage


def finding(index, *, description="Brief explanation.", endpoints=(), references=(1,)):
    return Finding(
        title=f"Synthetic finding {index}", classification="Review",
        description=description, references=tuple(references),
        suggested_next_step=f"Verify expected activity for finding {index}.",
        triggering_rule=f"Synthetic rule {index} was satisfied.",
        why_it_matters=f"Synthetic context {index} may aid an investigation.",
        endpoints=tuple(endpoints))


class FindingsUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def _render(self, findings, width=1000, height=650):
        page = FindingsPage()
        page.resize(width, height)
        page.set_findings(findings)
        page.show()
        self.app.processEvents()
        return page

    def test_selecting_finding_updates_each_detail_field_once(self):
        first = finding(1, description="First description", endpoints=("10.0.0.1", "10.0.0.2"))
        second = finding(2, description="Second description", endpoints=("10.0.0.3", "10.0.0.4"))
        page = self._render([first, second])
        page.list.setCurrentRow(1)
        self.app.processEvents()
        self.assertEqual(page.detail_title.text(), second.title)
        self.assertEqual(page.detail_description.text(), second.description)
        self.assertEqual(page.detail_endpoints.text(), "10.0.0.3 → 10.0.0.4")
        self.assertEqual(page.detail_rule.text(), second.triggering_rule)
        self.assertEqual(page.detail_why.text(), second.why_it_matters)
        self.assertEqual(page.detail_next.text(), second.suggested_next_step)
        detail_texts = [label.text() for label in page.detail_content.findChildren(QLabel)]
        self.assertEqual(detail_texts.count(second.description), 1)
        self.assertNotIn(first.description, detail_texts)
        page.close()

    def test_long_description_and_ipv6_endpoints_wrap_without_overlap(self):
        long_finding = finding(
            1,
            description=("Long wrapped description used to verify natural master-detail layout behavior. ") * 20,
            endpoints=("2001:db8:1111:2222:3333:4444:5555:6666",
                       "2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff"),
            references=range(1, 200))
        page = self._render([long_finding], width=760, height=520)
        labels = (page.detail_description, page.detail_endpoints, page.detail_rule,
                  page.detail_why, page.detail_evidence, page.detail_next)
        for label in labels:
            self.assertTrue(label.wordWrap())
            self.assertGreater(label.width(), 0)
            self.assertGreaterEqual(label.height() + 1, label.heightForWidth(label.width()))
        ranges = []
        for label in labels:
            top = label.mapTo(page.details_body, label.rect().topLeft()).y()
            ranges.append((top, top + label.height() - 1))
        for previous, current in zip(ranges, ranges[1:]):
            self.assertLess(previous[1], current[0])
        page.close()

    def test_details_panel_scrolls_for_large_content_and_many_findings(self):
        findings = [finding(index, description=("Scrollable details content. " * 35),
                            references=range(1, 50)) for index in range(12)]
        page = self._render(findings, width=780, height=400)
        self.assertGreater(page.list.verticalScrollBar().maximum(), 0)
        self.assertGreater(page.details_scroll.verticalScrollBar().maximum(), 0)
        page.close()

    def test_double_click_and_button_emit_complete_evidence_set(self):
        references = tuple(range(1, 1001))
        page = self._render([finding(1, references=references)])
        received = []
        page.packets_requested.connect(received.append)
        page._open_supporting_packet(page.list.item(0))
        page.view_packets_button.click()
        self.assertEqual(received, [references, references])
        self.assertIn("1,000 supporting packets", page.detail_evidence.text())
        page.close()

    def test_no_findings_uses_empty_state(self):
        page = self._render([])
        self.assertEqual(page.list.count(), 0)
        self.assertTrue(page.empty_state.isVisible())
        self.assertFalse(page.detail_content.isVisible())
        self.assertIn("No findings", page.empty_state.text())
        page.close()

    def test_resizing_and_font_scaling_preserve_readable_details(self):
        item = finding(1, description="Scale-aware detail text. " * 20,
                       endpoints=("2001:db8:1:2:3:4:5:6", "2001:db8:7:8:9:a:b:c"))
        page = self._render([item], width=1100, height=700)
        page.resize(650, 430)
        scaled = QFont(page.font())
        scaled.setPointSizeF(max(15.0, scaled.pointSizeF() * 1.5))
        page.setFont(scaled)
        self.app.processEvents()
        for label in (page.detail_description, page.detail_endpoints, page.detail_rule,
                      page.detail_why, page.detail_next):
            self.assertGreater(label.height(), 0)
            self.assertGreaterEqual(label.height() + 1, label.heightForWidth(label.width()))
        self.assertGreater(page.details_scroll.viewport().width(), 0)
        page.close()


if __name__ == "__main__":
    unittest.main()
