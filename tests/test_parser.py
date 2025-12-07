#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for create_db.py parsing functions."""

import pytest

from create_db import get_source, parse_property, parse_property_inetnum


class TestGetSource:
    """Tests for get_source function."""

    def test_afrinic(self):
        assert get_source("afrinic.db.gz") == b"afrinic"
        assert get_source("afrinic.db") == b"afrinic"

    def test_apnic(self):
        assert get_source("apnic.db.inetnum.gz") == b"apnic"
        assert get_source("apnic.db.inet6num.gz") == b"apnic"

    def test_arin(self):
        assert get_source("arin.db.gz") == b"arin"
        assert get_source("arin.db") == b"arin"

    def test_lacnic(self):
        assert get_source("lacnic.db.gz") == b"lacnic"
        assert get_source("delegated-lacnic-extended-latest") == b"lacnic"

    def test_ripe(self):
        assert get_source("ripe.db.inetnum.gz") == b"ripe"
        assert get_source("ripe.db.inet6num.gz") == b"ripe"

    def test_unknown(self):
        assert get_source("unknown.db") is None
        assert get_source("other.gz") is None


class TestParseProperty:
    """Tests for parse_property function."""

    def test_simple_property(self):
        block = b"netname: EXAMPLE-NET\ndescr: Example network"
        assert parse_property(block, b"netname") == "EXAMPLE-NET"
        assert parse_property(block, b"descr") == "Example network"

    def test_property_not_found(self):
        block = b"netname: EXAMPLE-NET"
        assert parse_property(block, b"descr") is None

    def test_multiline_property(self):
        block = b"descr: Line one\ndescr: Line two\ndescr: Line three"
        result = parse_property(block, b"descr")
        assert "Line one" in result
        assert "Line two" in result
        assert "Line three" in result

    def test_property_with_whitespace(self):
        block = b"netname:   EXAMPLE-NET   "
        assert parse_property(block, b"netname") == "EXAMPLE-NET"

    def test_property_with_special_chars(self):
        block = b"descr: Example with \xe4\xf6\xfc chars"
        result = parse_property(block, b"descr")
        assert result is not None
        assert "Example with" in result

    def test_empty_block(self):
        block = b""
        assert parse_property(block, b"netname") is None


class TestParsePropertyInetnum:
    """Tests for parse_property_inetnum function."""

    def test_ipv4_range(self):
        block = b"inetnum: 192.168.0.0 - 192.168.255.255"
        result = parse_property_inetnum(block)
        assert result is not None
        assert isinstance(result, list)
        assert str(result[0]) == "192.168.0.0/16"

    def test_ipv4_range_with_spaces(self):
        block = b"inetnum:   10.0.0.0   -   10.255.255.255  "
        result = parse_property_inetnum(block)
        assert result is not None
        assert isinstance(result, list)

    def test_ipv4_cidr_direct(self):
        block = b"inetnum: 192.168.1.0/24"
        result = parse_property_inetnum(block)
        assert result == b"192.168.1.0/24"

    def test_ipv4_incomplete_three_octets(self):
        # LACNIC format: 177.46.7/24
        block = b"inetnum: 177.46.7/24"
        result = parse_property_inetnum(block)
        assert result == b"177.46.7.0/24"

    def test_ipv4_incomplete_two_octets(self):
        # LACNIC format: 148.204/16
        block = b"inetnum: 148.204/16"
        result = parse_property_inetnum(block)
        assert result == b"148.204.0.0/16"

    def test_ipv6(self):
        block = b"inet6num: 2001:db8::/32"
        result = parse_property_inetnum(block)
        assert result == b"2001:db8::/32"

    def test_ipv6_full(self):
        block = b"inet6num: 2001:0db8:0000:0000:0000:0000:0000:0000/128"
        result = parse_property_inetnum(block)
        assert b"2001:" in result

    def test_route_ipv4(self):
        block = b"route: 8.8.8.0/24"
        result = parse_property_inetnum(block)
        assert result == b"8.8.8.0/24"

    def test_route6_ipv6(self):
        block = b"route6: 2001:db8::/32"
        result = parse_property_inetnum(block)
        assert result == b"2001:db8::/32"

    def test_no_inetnum(self):
        block = b"netname: EXAMPLE\ndescr: No IP here"
        result = parse_property_inetnum(block)
        assert result is None

    def test_empty_block(self):
        result = parse_property_inetnum(b"")
        assert result is None

    def test_ipv4_range_non_cidr_boundary(self):
        # Range that spans multiple CIDRs
        block = b"inetnum: 192.168.0.0 - 192.168.1.255"
        result = parse_property_inetnum(block)
        assert result is not None
        assert isinstance(result, list)
        # Should return multiple CIDRs or a single one that covers both
        assert len(result) >= 1


class TestParsePropertyIntegration:
    """Integration tests with realistic WHOIS block data."""

    def test_ripe_block(self):
        block = b"""inetnum:        193.0.0.0 - 193.0.7.255
netname:        RIPE-NCC
descr:          RIPE Network Coordination Centre
country:        NL
admin-c:        RIPE-NCC-MNT
tech-c:         RIPE-NCC-MNT
status:         ASSIGNED PI
mnt-by:         RIPE-NCC-MNT
created:        2003-03-17T12:15:57Z
last-modified:  2017-12-12T11:51:18Z
source:         RIPE
cust_source: ripe"""

        inetnum = parse_property_inetnum(block)
        assert inetnum is not None

        netname = parse_property(block, b"netname")
        assert netname == "RIPE-NCC"

        country = parse_property(block, b"country")
        assert country == "NL"

        status = parse_property(block, b"status")
        assert status == "ASSIGNED PI"

        source = parse_property(block, b"cust_source")
        assert source == "ripe"

    def test_apnic_block(self):
        block = b"""inetnum:        1.0.0.0 - 1.0.0.255
netname:        APNIC-LABS
descr:          APNIC and Cloudflare DNS Resolver project
descr:          Routed globally by AS13335/Cloudflare
country:        AU
admin-c:        APNIC-HM
tech-c:         APNIC-HM
mnt-by:         APNIC-HM
status:         ASSIGNED PORTABLE
last-modified:  2020-07-15T13:10:57Z
source:         APNIC
cust_source: apnic"""

        inetnum = parse_property_inetnum(block)
        assert inetnum is not None

        netname = parse_property(block, b"netname")
        assert netname == "APNIC-LABS"

        # Multi-line description
        descr = parse_property(block, b"descr")
        assert "APNIC and Cloudflare" in descr
        assert "Routed globally" in descr

    def test_arin_route_block(self):
        block = b"""route:          8.8.8.0/24
descr:          Google DNS
origin:         AS15169
mnt-by:         GOOGLE-MNT
source:         ARIN
cust_source: arin"""

        inetnum = parse_property_inetnum(block)
        assert inetnum == b"8.8.8.0/24"

        origin = parse_property(block, b"origin")
        assert origin == "AS15169"

    def test_ipv6_block(self):
        block = b"""inet6num:       2001:db8::/32
netname:        DOCUMENTATION
descr:          Documentation prefix
country:        ZZ
status:         ASSIGNED
source:         TEST
cust_source: ripe"""

        inetnum = parse_property_inetnum(block)
        assert inetnum == b"2001:db8::/32"

        netname = parse_property(block, b"netname")
        assert netname == "DOCUMENTATION"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
