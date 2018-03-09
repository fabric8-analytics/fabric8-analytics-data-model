"""Tests for the data_importer module (to be done)."""

from graph_importer import *
import pytest


def test_parse_int_or_none_integer_input():
    """Test the function parse_int_or_none() for integer inputs."""
    assert 0 == parse_int_or_none(0)
    assert 1 == parse_int_or_none(1)
    assert -1 == parse_int_or_none(-1)


def test_parse_int_or_none_float_input():
    """Test the function parse_int_or_none() for float inputs."""
    assert 0 == parse_int_or_none(0.0)
    assert 1 == parse_int_or_none(1.0)
    assert 1 == parse_int_or_none(1.1)
    assert 2 == parse_int_or_none(1.9)
    assert -1 == parse_int_or_none(-1)


def test_parse_int_or_none_for_string_input():
    """Test the function parse_int_or_none() for string input."""
    assert 42 == parse_int_or_none("42")
    assert 42 == parse_int_or_none("42.1")
    assert 42 == parse_int_or_none("41.9")
    assert -42 == parse_int_or_none("-42")
    assert -42 == parse_int_or_none("-42.1")
    assert -42 == parse_int_or_none("-41.9")


def test_parse_int_or_none_for_invalid_input():
    """Test the function parse_int_or_none() for invalid input."""
    assert parse_int_or_none(None) is None
    assert parse_int_or_none(True) is None
    assert parse_int_or_none(False) is None
    assert parse_int_or_none([]) is None
    assert parse_int_or_none({}) is None
