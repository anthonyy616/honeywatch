"""Rule fixture definitions.

Every shipped rule needs a positive fixture (must fire) and a near-miss
fixture (must not fire). Fixture metadata is machine readable so
``honeywatch rules test`` and CI can both consume it.
"""

from __future__ import annotations