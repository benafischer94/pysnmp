"""
Regression tests for VACM configuration and access control.

Covers:
  - etingof/pysnmp#206: VACM wildcard mask caused AttributeError on asNumbers()
    (vacmViewTreeFamilyMask was read as Integer32 instead of OctetString)
  - etingof/pysnmp#149: VACM context table leaked entries when users were deleted
"""

import asyncio
import pytest

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import cmdrsp, context as rfc3413_context
from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    get_cmd,
    next_cmd,
)

VACM_TEST_PORT = 19162


async def _make_agent(port: int, mask: bytes) -> engine.SnmpEngine:
    """Start a minimal SNMPv2c agent with a VACM view using the given mask."""
    snmpEngine = engine.SnmpEngine()
    config.add_transport(
        snmpEngine,
        udp.DOMAIN_NAME,
        udp.UdpTransport().open_server_mode(("localhost", port)),
    )
    config.add_v1_system(snmpEngine, "public", "public")
    config.add_context(snmpEngine, b"")
    config.add_vacm_group(snmpEngine, "testgroup", 2, "public")
    config.add_vacm_access(
        snmpEngine, "testgroup", b"", 2, 1, "exact", "testView", "", ""
    )
    # Use caller-supplied mask so tests can exercise both empty and wildcard paths
    config.add_vacm_view(snmpEngine, "testView", "included", (1, 3, 6, 1, 2, 1), mask)
    snmpContext = rfc3413_context.SnmpContext(snmpEngine)
    cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
    cmdrsp.NextCommandResponder(snmpEngine, snmpContext)
    snmpEngine.transport_dispatcher.job_started(1)
    snmpEngine.open_dispatcher()
    await asyncio.sleep(0.3)
    return snmpEngine


def _stop_agent(snmpEngine: engine.SnmpEngine) -> None:
    snmpEngine.transport_dispatcher.job_finished(1)
    snmpEngine.close_dispatcher()


# ---------------------------------------------------------------------------
# #206 — VACM wildcard mask must not raise AttributeError on asNumbers()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_vacm_wildcard_mask_get():
    """
    Regression: etingof/pysnmp#206

    A VACM view configured with a non-trivial bitmask (not all-ones) caused
    rfc3415.py to call asNumbers() on an Integer32 instead of OctetString,
    raising AttributeError.  Verify that a GET succeeds when a wildcard mask
    is in use.
    """
    # 0xfe = 11111110 — wildcards the last bit of the first sub-identifier
    snmpEngine = await _make_agent(VACM_TEST_PORT, b"\xfe\xff\xff")
    try:
        with SnmpEngine() as mgr:
            ei, es, _, vbs = await get_cmd(
                mgr,
                CommunityData("public"),
                await UdpTransportTarget.create(
                    ("localhost", VACM_TEST_PORT), timeout=1, retries=0
                ),
                ContextData(),
                ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
            )
        assert ei is None, f"Unexpected errorIndication: {ei}"
        assert int(es) == 0, f"Unexpected errorStatus: {es.prettyPrint()}"
        assert len(vbs) == 1
        assert "sysDescr" in vbs[0][0].prettyPrint()
    finally:
        _stop_agent(snmpEngine)


@pytest.mark.asyncio
async def test_vacm_empty_mask_get():
    """
    Complement to the wildcard test: an empty mask (all-ones, exact match)
    must also work correctly.
    """
    snmpEngine = await _make_agent(VACM_TEST_PORT + 1, b"")
    try:
        with SnmpEngine() as mgr:
            ei, es, _, vbs = await get_cmd(
                mgr,
                CommunityData("public"),
                await UdpTransportTarget.create(
                    ("localhost", VACM_TEST_PORT + 1), timeout=1, retries=0
                ),
                ContextData(),
                ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
            )
        assert ei is None, f"Unexpected errorIndication: {ei}"
        assert int(es) == 0
        assert len(vbs) == 1
    finally:
        _stop_agent(snmpEngine)


# ---------------------------------------------------------------------------
# #149 — VACM context table must not leak entries after delete_vacm_user()
# ---------------------------------------------------------------------------


def _count_vacm_contexts(snmpEngine: engine.SnmpEngine) -> int:
    mibBuilder = snmpEngine.get_mib_builder()
    (vacmContextName,) = mibBuilder.import_symbols(
        "SNMP-VIEW-BASED-ACM-MIB", "vacmContextName"
    )
    count = 0
    node = vacmContextName
    while True:
        try:
            node = vacmContextName.getNextNode(node.name)
            count += 1
        except Exception:
            break
    return count


def test_vacm_context_table_no_leak_after_delete():
    """
    Regression: etingof/pysnmp#149

    Adding then deleting VACM users with named contexts must not leave orphaned
    rows in the vacmContextTable.
    """
    snmpEngine = engine.SnmpEngine()

    assert _count_vacm_contexts(snmpEngine) == 0

    contexts = [f"ctx{i}".encode() for i in range(5)]
    for i, ctx in enumerate(contexts):
        config.add_vacm_user(
            snmpEngine, 2, f"user{i}", "noAuthNoPriv", (1, 3, 6), contextName=ctx
        )

    assert _count_vacm_contexts(snmpEngine) == len(contexts)

    for i, ctx in enumerate(contexts):
        config.delete_vacm_user(
            snmpEngine, 2, f"user{i}", "noAuthNoPriv", (1, 3, 6), contextName=ctx
        )

    assert _count_vacm_contexts(snmpEngine) == 0


def test_vacm_context_table_no_leak_repeated_add_delete():
    """
    Repeated add/delete cycles for the same context name must not accumulate
    entries in the vacmContextTable.
    """
    snmpEngine = engine.SnmpEngine()

    for _ in range(10):
        config.add_vacm_user(
            snmpEngine, 2, "cycleuser", "noAuthNoPriv", (1, 3, 6), contextName=b"ctx0"
        )
        config.delete_vacm_user(
            snmpEngine, 2, "cycleuser", "noAuthNoPriv", (1, 3, 6), contextName=b"ctx0"
        )

    assert _count_vacm_contexts(snmpEngine) == 0
