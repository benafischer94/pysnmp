"""
Tests for how pysnmp handles malformed response PDUs from non-conformant agents.

Covers:
  - etingof/pysnmp#119: SNMPv2c response with OID containing invalid 0x80 byte
    (non-minimal BER multi-byte subidentifier) is rejected by pyasn1 and
    silently discarded; snmpInASNParseErrs is incremented.

  - etingof/pysnmp#105: SNMPv1 response containing a Counter64 value (tag 0x46)
    is rejected because Counter64 is not valid in SNMPv1; the PDU is silently
    discarded and snmpInASNParseErrs is incremented.

In both cases the current behaviour is: the malformed message is counted and
dropped rather than crashing or propagating an unhandled exception.  These
tests lock in that behaviour so regressions are caught early.
"""

import pytest

from pysnmp.entity import engine


def _count_asn_parse_errs(snmpEngine) -> int:
    mibBuilder = snmpEngine.get_mib_builder()
    (snmpInASNParseErrs,) = mibBuilder.import_symbols(
        "__SNMPv2-MIB", "snmpInASNParseErrs"
    )
    return int(snmpInASNParseErrs.syntax)


def _build_v2c_response_with_bad_oid() -> bytes:
    """
    SNMPv2c GetResponse whose single varbind contains an OID with a
    non-minimal (leading 0x80) subidentifier byte — invalid per DER/BER.

    The OID encodes 1.3.6.1.4.1.32584.1.8.5.1.0 with the 32584 arc encoded
    as [0x80, 0x81, 0xfe, 0x48] instead of the minimal [0x81, 0xfe, 0x48].
    This is the exact encoding seen in the packet capture from issue #119.
    """
    # OID TLV with 0x80 leading byte in one subidentifier
    oid_enc = bytes([
        0x06,
        0x0E,
        0x2B,
        0x06,
        0x01,
        0x04,
        0x01,
        0x80,
        0x81,
        0xFE,
        0x48,
        0x01,
        0x08,
        0x05,
        0x01,
        0x00,
    ])
    val_enc = bytes([0x02, 0x01, 0x0C])  # INTEGER 12
    varbind = bytes([0x30, len(oid_enc) + len(val_enc)]) + oid_enc + val_enc
    varbindlist = bytes([0x30, len(varbind)]) + varbind
    pdu_body = (
        bytes([0x02, 0x04, 0x75, 0xF6, 0x71, 0x99])  # request-id
        + bytes([0x02, 0x01, 0x00])  # error-status 0
        + bytes([0x02, 0x01, 0x00])  # error-index 0
        + varbindlist
    )
    pdu = bytes([0xA2, len(pdu_body)]) + pdu_body
    community = bytes([0x04, 0x06]) + b"public"
    version = bytes([0x02, 0x01, 0x01])  # version 1 = SNMPv2c
    msg_body = version + community + pdu
    return bytes([0x30, len(msg_body)]) + msg_body


def _build_v1_response_with_counter64() -> bytes:
    """
    SNMPv1 GetResponse whose single varbind value is Counter64 (tag 0x46).
    Counter64 does not exist in SNMPv1, so this is non-conformant.
    net-snmp accepts such responses; pysnmp currently rejects them.
    """
    oid_enc = bytes([
        0x06,
        0x09,
        0x2B,
        0x06,
        0x01,
        0x02,
        0x01,
        0x01,
        0x01,
        0x00,
    ])  # 1.3.6.1.2.1.1.1.0
    c64_enc = bytes([0x46, 0x01, 0x2A])  # Counter64 = 42
    varbind = bytes([0x30, len(oid_enc) + len(c64_enc)]) + oid_enc + c64_enc
    varbindlist = bytes([0x30, len(varbind)]) + varbind
    pdu_body = (
        bytes([0x02, 0x01, 0x01])  # request-id 1
        + bytes([0x02, 0x01, 0x00])  # error-status 0
        + bytes([0x02, 0x01, 0x00])  # error-index 0
        + varbindlist
    )
    pdu = bytes([0xA2, len(pdu_body)]) + pdu_body
    community = bytes([0x04, 0x06]) + b"public"
    version = bytes([0x02, 0x01, 0x00])  # version 0 = SNMPv1
    msg_body = version + community + pdu
    return bytes([0x30, len(msg_body)]) + msg_body


# ---------------------------------------------------------------------------
# #119 — OID with invalid leading 0x80 byte
# ---------------------------------------------------------------------------


def test_invalid_oid_0x80_increments_asn_parse_errs():
    """
    etingof/pysnmp#119: a response PDU containing an OID with a non-minimal
    0x80 leading byte must be silently discarded and snmpInASNParseErrs
    must be incremented by 1.  No unhandled exception should propagate.
    """
    snmpEngine = engine.SnmpEngine()
    before = _count_asn_parse_errs(snmpEngine)

    msg = _build_v2c_response_with_bad_oid()
    # Feed raw bytes directly to the message dispatcher (simulates a received
    # UDP datagram from a non-conformant agent)
    snmpEngine.message_dispatcher.receive_message(
        snmpEngine,
        (1, 3, 6, 1, 6, 1, 1),  # snmpUDPDomain
        ("127.0.0.1", 161),
        msg,
    )

    after = _count_asn_parse_errs(snmpEngine)
    assert after == before + 1, (
        f"Expected snmpInASNParseErrs to increase by 1 (was {before}, now {after})"
    )


def test_invalid_oid_0x80_does_not_raise():
    """
    etingof/pysnmp#119: receiving a PDU with a bad OID must never raise an
    unhandled exception from receive_message().
    """
    snmpEngine = engine.SnmpEngine()
    msg = _build_v2c_response_with_bad_oid()
    # Must not raise
    snmpEngine.message_dispatcher.receive_message(
        snmpEngine,
        (1, 3, 6, 1, 6, 1, 1),
        ("127.0.0.1", 161),
        msg,
    )


# ---------------------------------------------------------------------------
# #105 — Counter64 in SNMPv1 response
# ---------------------------------------------------------------------------


def test_counter64_in_v1_increments_asn_parse_errs():
    """
    etingof/pysnmp#105: a SNMPv1 response PDU containing a Counter64 value
    must be silently discarded and snmpInASNParseErrs must be incremented.
    Counter64 is not defined in SNMPv1; some agents send it anyway.
    """
    snmpEngine = engine.SnmpEngine()
    before = _count_asn_parse_errs(snmpEngine)

    msg = _build_v1_response_with_counter64()
    snmpEngine.message_dispatcher.receive_message(
        snmpEngine,
        (1, 3, 6, 1, 6, 1, 1),
        ("127.0.0.1", 161),
        msg,
    )

    after = _count_asn_parse_errs(snmpEngine)
    assert after == before + 1, (
        f"Expected snmpInASNParseErrs to increase by 1 (was {before}, now {after})"
    )


def test_counter64_in_v1_does_not_raise():
    """
    etingof/pysnmp#105: receiving a SNMPv1 PDU with Counter64 must never
    raise an unhandled exception from receive_message().
    """
    snmpEngine = engine.SnmpEngine()
    msg = _build_v1_response_with_counter64()
    # Must not raise
    snmpEngine.message_dispatcher.receive_message(
        snmpEngine,
        (1, 3, 6, 1, 6, 1, 1),
        ("127.0.0.1", 161),
        msg,
    )
