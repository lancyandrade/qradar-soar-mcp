"""P2-01 AC, lab half: both catalog backends give an equivalent ``Catalog`` (D26 (b)).

SCAFFOLD. It cannot pass today and is not expected to: ``ExportBackend`` refuses every
load because no export contract is verified (P2-00c). An HTTP 403, a
``catalog_unavailable`` refusal or any other failure to obtain an export catalog is a
**failure** of this test, never a pass and never a skip once the test is opted into.

Two opt-ins, both required:

1. ``SOAR_TEST_ENABLE`` includes ``lab`` (the T4 guard, ``tests/lab/guard.py``);
2. ``SOAR_TEST_CATALOG_EQUIVALENCE=authorised-export``, which the operator sets only
   after the owner has separately authorised the configuration-export request for that
   run (``POST /configurations/exports``; D26 (b), 08 §25.1) and an export-capable key
   in the lab org has been issued through ``docs/ACCESS-CHECKLIST.md``.

Without (2) the test skips with the reason. Even with it, every request still goes
through :class:`tests.lab.guard.ReadOnlyTransport`, which refuses export creation,
retrieval and history for every method. The export requests will need their own,
separately authorised transport (``docs/proposals/PHASE2-CLOSEOUT-PLAN.md`` §4.1),
reviewed with the export backend; the read-only guard is never widened for them.

Same appliance, same configuration state: one client loads ``collections``, then
``export``, then ``collections`` again. If the two ``collections`` catalogs differ, the
configuration changed during the run and the test fails as invalid evidence (never as a
pass). Differences are reported as paths, never values.
"""

from __future__ import annotations

import pytest

from qradar_soar_mcp.catalog.backends import build_backend
from tests.catalog_equivalence import catalog_differences, describe
from tests.lab.conftest import LAB_ENV
from tests.lab.guard import LabTarget

pytestmark = pytest.mark.lab

OPT_IN_VAR = "SOAR_TEST_CATALOG_EQUIVALENCE"
OPT_IN_VALUE = "authorised-export"


async def test_collections_and_export_catalogs_are_equivalent(t4_runtime, lab_target: LabTarget):
    if LAB_ENV.get(OPT_IN_VAR) != OPT_IN_VALUE:
        pytest.skip(
            f"{OPT_IN_VAR} is not {OPT_IN_VALUE!r}: the export request needs separate owner "
            "authorisation and an export-capable key (D26 (b)); the export backend is unverified"
        )
    rt, _ = t4_runtime
    client = rt.require_client()
    collections = await build_backend("collections", client).load()
    export = await build_backend("export", client).load()  # raises today: the AC is unmet
    after = await build_backend("collections", client).load()
    drift = catalog_differences(collections, after)
    assert drift == [], "configuration changed during the run: " + describe(drift)
    assert collections.source == "collections" and export.source == "export"
    assert collections.soar_version == export.soar_version
    assert collections.org_id == export.org_id == str(lab_target.org_id)
    diffs = catalog_differences(collections, export)
    assert diffs == [], describe(diffs)
