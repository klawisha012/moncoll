#!/usr/bin/env python3

import pytest

# Test for REQUEST-900-EXCLUSION-RULES-BEFORE-CRS
# This category contains exclusion rules that are typically customized per deployment.
# Since this is an example file (.conf.example), it may not be active in the current setup.
# No parametrized tests with payloads are required as there are no attack patterns defined.

def test_exclusion_rules_placeholder():
    """Placeholder test for exclusion rules category 900.

    Exclusion rules are deployment-specific and don't follow attack patterns.
    This test ensures the category is recognized but doesn't perform payload testing.
    """
    # This category doesn't require payload-based testing as it contains
    # custom exclusion rules rather than attack detection rules.
    assert True  # Placeholder assertion