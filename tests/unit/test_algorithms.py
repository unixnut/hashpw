#!/usr/bin/env python

"""Tests for `hashpw` package."""


import unittest
import re

## from hashpw import hashpw
from hashpw import cli
## from ..scaffolding.algorithms import AlgorithmGenericTests


# *** CLASSES ***
# This doesn't inherit from unittest.TestCase to avoid discovery happening for it
class AlgorithmGenericTests:
    """Stuff common to tests for all algorithms."""

    def setUp(self):
        cli.mode = self.alg_class.name
        self.alg_class.init(self.alg_class)
        self.hasher = cli.create_hasher(self.alg_class, None, cli.settings)

    def tearDown(self):
        """Tear down test fixtures, if any."""

    def test_new(self):
        """Test creation of a new hash."""
        hash = cli.make_hash(self.hasher, "foobie bletch")
        self.assertGreaterEqual(len(hash), self.alg_class.min_length, msg="Created hash is too short")
        # assertStartsWith
        self.assertRegex(hash, "^%s" % re.escape(self.alg_class.prefix), msg="Created hash doesn't start with prefix")


class TestMD5(AlgorithmGenericTests, unittest.TestCase):
    """Tests for MD5 algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = cli.MD5

    # This didn't work; wasn't called until mixin was put first
    ## def setUp(self):
    ##     """Set up test fixtures, if any."""
    ##     self.alg_class = cli.MD5
    ##     super().setUp()
    ## ... hack did work:   AlgorithmGenericTests.setUp(self)


class TestMD5(AlgorithmGenericTests, unittest.TestCase):
    """Tests for MD5 algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = cli.MD5


class TestApacheMD5(AlgorithmGenericTests, unittest.TestCase):
    """Tests for ApacheMD5 algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = cli.ApacheMD5


class TestApacheSHA1(AlgorithmGenericTests, unittest.TestCase):
    """Tests for ApacheSHA1 algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = cli.ApacheSHA1


class TestBlowfish(AlgorithmGenericTests, unittest.TestCase):
    """Tests for Blowfish algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = cli.Blowfish


class TestSHA256(AlgorithmGenericTests, unittest.TestCase):
    """Tests for SHA256 algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = cli.SHA256


class TestSHA512(AlgorithmGenericTests, unittest.TestCase):
    """Tests for SHA512 algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = cli.SHA512


class TestMySqlSHA1(AlgorithmGenericTests, unittest.TestCase):
    """Tests for MySqlSHA1 algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = cli.MySqlSHA1


class TestPhpass(AlgorithmGenericTests, unittest.TestCase):
    """Tests for Phpass algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = cli.Phpass


@unittest.skip("Algorithm unimplemented")
class TestPhpBB3(AlgorithmGenericTests, unittest.TestCase):
    """Tests for PhpBB3 algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = cli.PhpBB3


class TestSSHA(AlgorithmGenericTests, unittest.TestCase):
    """Tests for SSHA algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = cli.SSHA


class TestBasicMD5(AlgorithmGenericTests, unittest.TestCase):
    """Tests for BasicMD5 algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = cli.BasicMD5


class TestExtDes(AlgorithmGenericTests, unittest.TestCase):
    """Tests for ExtDes algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = cli.ExtDes


class TestCrypt(AlgorithmGenericTests, unittest.TestCase):
    """Tests for Crypt algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = cli.Crypt


class TestOldPassword(AlgorithmGenericTests, unittest.TestCase):
    """Tests for OldPassword algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = cli.OldPassword


if __name__ == '__main__':
    unittest.main()
