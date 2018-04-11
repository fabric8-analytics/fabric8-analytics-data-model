"""Tests for the data_importer module (to be done)."""

import data_importer
import pytest


def test_parse_int_or_none_for_integer_input():
    """Test the function parse_int_or_none() for integer inputs."""
    assert 0 == data_importer.parse_int_or_none(0)
    assert 1 == data_importer.parse_int_or_none(1)
    assert -1 == data_importer.parse_int_or_none(-1)


def test_parse_int_or_none_for_integer_input_overflows():
    """Test the function parse_int_or_none() for integer inputs."""
    # positive values overflow checks
    assert 65535 == data_importer.parse_int_or_none(65535)
    assert 65536 == data_importer.parse_int_or_none(65536)
    assert 2147483647 == data_importer.parse_int_or_none(2147483647)
    assert 2147483648 == data_importer.parse_int_or_none(2147483648)
    # negative values overflow checks
    assert -65535 == data_importer.parse_int_or_none(-65535)
    assert -65536 == data_importer.parse_int_or_none(-65536)
    assert -2147483647 == data_importer.parse_int_or_none(-2147483647)
    assert -2147483648 == data_importer.parse_int_or_none(-2147483648)


def test_parse_int_or_none_for_float_input():
    """Test the function parse_int_or_none() for float inputs."""
    assert 0 == data_importer.parse_int_or_none(0.0)
    assert 1 == data_importer.parse_int_or_none(1.0)
    assert 1 == data_importer.parse_int_or_none(1.1)
    assert 1 == data_importer.parse_int_or_none(1.9)
    assert -1 == data_importer.parse_int_or_none(-1)


def test_parse_int_or_none_for_string_input():
    """Test the function parse_int_or_none() for string input."""
    assert 42 == data_importer.parse_int_or_none("42")
    assert 42 == data_importer.parse_int_or_none("42.1")
    assert 41 == data_importer.parse_int_or_none("41.9")
    assert -42 == data_importer.parse_int_or_none("-42")
    assert -42 == data_importer.parse_int_or_none("-42.1")
    assert -41 == data_importer.parse_int_or_none("-41.9")


def test_parse_int_or_none_for_unicode_string_input():
    """Test the function parse_int_or_none() for Unicode string input."""
    assert 42 == data_importer.parse_int_or_none(u"42")
    assert 42 == data_importer.parse_int_or_none(u"42.1")
    assert 41 == data_importer.parse_int_or_none(u"41.9")
    assert -42 == data_importer.parse_int_or_none(u"-42")
    assert -42 == data_importer.parse_int_or_none(u"-42.1")
    assert -41 == data_importer.parse_int_or_none(u"-41.9")


def test_parse_int_or_none_for_invalid_input():
    """Test the function parse_int_or_none() for invalid input."""
    assert data_importer.parse_int_or_none(None) is None
    assert data_importer.parse_int_or_none(True) == 1
    assert data_importer.parse_int_or_none(False) == 0
    assert data_importer.parse_int_or_none([]) is None
    assert data_importer.parse_int_or_none({}) is None


def test_get_exception_msg():
    """Test the function _get_exception_msg()."""
    e1 = ValueError('hello world!')
    assert data_importer._get_exception_msg("prefix", e1) == "prefix: hello world!"

    e2 = ValueError('hello world!')
    assert data_importer._get_exception_msg("", e2) == ": hello world!"


def test_import_epv_http():
    """Test the function import_epv_http()."""
    with pytest.raises(RuntimeError) as e:
        import_epv_http(None, [])


if __name__ == '__main__':
    test_parse_int_or_none_for_integer_input()
    test_parse_int_or_none_for_integer_input_overflow()
    test_parse_int_or_none_for_float_input()
    test_parse_int_or_none_for_string_input()
    test_parse_int_or_none_for_unicode_string_input()
    test_parse_int_or_none_for_invalid_input()
    test_get_exception_msg()
    test_import_epv_http()
