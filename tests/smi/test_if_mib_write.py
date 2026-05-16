"""
Tests for write operations on IF-MIB table entries.

Covers:
  - etingof/pysnmp#316: WrongValueError raised when writing ifIndex into
    ifEntry via write_variables().  The error incorrectly referenced
    IF-MIB::ifTestId (1.3.6.1.2.1.31.1.3.1.1.1) instead of the column
    being written.

    Root cause: MibScalarInstance.setValue() converted None to noValue and
    then called syntax.setValue(noValue) which triggered a PyAsn1Error for
    types like TestAndIncr that compare the value with __ne__ before
    accepting it.  Fixed by returning syntax.clone() when value is None.
"""

import pytest

from pysnmp.entity import engine
from pysnmp.entity.rfc3413 import context as rfc3413_context
from pysnmp.smi import rfc1902, view


def _make_mib_context():
    snmpEngine = engine.SnmpEngine()
    snmpContext = rfc3413_context.SnmpContext(snmpEngine)
    mibBuilder = snmpContext.get_mib_instrum().get_mib_builder()
    mvc = view.MibViewController(mibBuilder)
    # Trigger IF-MIB loading
    rfc1902.ObjectIdentity("IF-MIB", "ifEntry").resolve_with_mib(mvc)
    return snmpContext, mibBuilder


def test_write_if_entry_ifindex_no_error():
    """
    Writing ifIndex (column 1) into ifEntry must not raise WrongValueError.

    Regression for etingof/pysnmp#316 where write_variables() raised:
      WrongValueError({'name': (1,3,6,1,2,1,31,1,3,1,1,1), ...})
    pointing at IF-MIB::ifTestId instead of the column being written.

    Fixed in MibScalarInstance.setValue: when value is None, return
    syntax.clone() instead of syntax.setValue(noValue).
    """
    snmpContext, mibBuilder = _make_mib_context()
    (ifEntry,) = mibBuilder.import_symbols("IF-MIB", "ifEntry")
    tbl_ndx = ifEntry.getInstIdFromIndices(1)

    result = snmpContext.get_mib_instrum().write_variables(
        (ifEntry.name + (1,) + tbl_ndx, 1),
    )
    assert result is not None


def test_write_if_entry_ifdescr_no_error():
    """
    Writing ifDescr (column 2) into ifEntry must not raise WrongValueError.
    """
    snmpContext, mibBuilder = _make_mib_context()
    (ifEntry,) = mibBuilder.import_symbols("IF-MIB", "ifEntry")
    tbl_ndx = ifEntry.getInstIdFromIndices(1)

    result = snmpContext.get_mib_instrum().write_variables(
        (ifEntry.name + (2,) + tbl_ndx, "eth0"),
    )
    assert result is not None
