#!/usr/bin/env python

"""Tests for `hashpw` package."""


import unittest
import re

## from hashpw import hashpw
import hashpw
## from ..scaffolding.algorithms import AlgorithmGenericTests


# *** CLASSES ***
# This doesn't inherit from unittest.TestCase to avoid discovery happening for it
class AlgorithmGenericTests:
    """Stuff common to tests for all algorithms."""

    def tearDown(self):
        """Tear down test fixtures, if any."""

    def test_new(self):
        """Test creation of a new hash."""
        hash = self.hasher.hash("foobie bletch")
        self.assertGreaterEqual(len(hash), self.alg_class.min_length, msg="Created hash is too short")
        # assertStartsWith
        self.assertRegex(hash, "^%s" % re.escape(self.alg_class.prefix), msg="Created hash doesn't start with prefix")


class AlgorithmUnsaltedMixin(AlgorithmGenericTests):
    def setUp(self):
        self.alg_class.init(self.alg_class)
        self.hasher = self.alg_class()


class AlgorithmSaltedMixin(AlgorithmGenericTests):
    def setUp(self):
        self.alg_class.init(self.alg_class)
        self.hasher = self.alg_class(None)


class TestMD5(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for MD5 algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = hashpw.MD5

    # This didn't work; wasn't called until mixin was put first
    ## def setUp(self):
    ##     """Set up test fixtures, if any."""
    ##     self.alg_class = hashpw.MD5
    ##     super().setUp()
    ## ... hack did work:   AlgorithmGenericTests.setUp(self)


class TestApacheMD5(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for ApacheMD5 algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = hashpw.ApacheMD5


class TestApacheSHA1(AlgorithmUnsaltedMixin, unittest.TestCase):
    """Tests for ApacheSHA1 algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = hashpw.ApacheSHA1


class TestBlowfish(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for Blowfish algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = hashpw.Blowfish


class TestSHA256(AlgorithmGenericTests, unittest.TestCase):
    """Tests for SHA256 algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = hashpw.SHA256

    def setUp(self):
        self.alg_class.init(self.alg_class, long_salt=True)
        self.hasher = self.alg_class(None)


class TestSHA512(AlgorithmGenericTests, unittest.TestCase):
    """Tests for SHA512 algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = hashpw.SHA512

    def setUp(self):
        self.alg_class.init(self.alg_class, long_salt=True)
        self.hasher = self.alg_class(None)


class TestMySqlSHA1(AlgorithmUnsaltedMixin, unittest.TestCase):
    """Tests for MySqlSHA1 algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = hashpw.MySqlSHA1


class TestPhpass(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for Phpass algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = hashpw.Phpass


@unittest.skip("Algorithm unimplemented")
class TestPhpBB3(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for PhpBB3 algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = hashpw.PhpBB3


class TestSSHA(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for SSHA algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = hashpw.SSHA


class TestBasicMD5(AlgorithmUnsaltedMixin, unittest.TestCase):
    """Tests for BasicMD5 algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = hashpw.BasicMD5


class TestExtDes(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for ExtDes algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = hashpw.ExtDes


class TestCrypt(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for Crypt algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = hashpw.Crypt


class TestOldPassword(AlgorithmUnsaltedMixin, unittest.TestCase):
    """Tests for OldPassword algorithm."""

    @classmethod
    def setUpClass(cls):
        cls.alg_class = hashpw.OldPassword


if __name__ == '__main__':
    unittest.main()
