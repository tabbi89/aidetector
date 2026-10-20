"""Broken report fixtures prove coverage gates cannot green a skipped DB suite."""
import xml.etree.ElementTree as ET

import pytest

from scripts.check_coverage import check_report


def report(**counts):
    return ET.fromstring('<testsuites><testsuite tests="20" ' + " ".join(
        f'{key}="{value}"' for key, value in counts.items()
    ) + "/></testsuites>")


TOTALS = {"covered_lines": 90, "num_statements": 100,
          "covered_branches": 80, "num_branches": 100}


def test_complete_coverage_report_passes():
    assert check_report(TOTALS, report()) == []


@pytest.mark.parametrize("field", ["skipped", "failures", "errors"])
def test_non_green_suite_cannot_supply_baseline(field):
    assert any(field in error for error in check_report(TOTALS, report(**{field: 1})))


@pytest.mark.parametrize("field", ["covered_lines", "covered_branches"])
def test_each_coverage_floor_is_enforced(field):
    assert check_report({**TOTALS, field: 0}, report())


def test_empty_suite_is_rejected():
    assert check_report(TOTALS, ET.fromstring('<testsuite tests="0"/>'))
