#!/usr/bin/env python

"""Tests for `hashpw` package."""


from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

import logging
import os
import unittest
import re

## from hashpw import hashpw
import hashpw
## from ..scaffolding.algorithms import AlgorithmGenericTests


# *** CLASSES ***
# == Test scaffolding ==
# This doesn't inherit from unittest.TestCase to avoid discovery happening for it
class AlgorithmGenericTests:
    """Stuff common to tests for all algorithms."""

    @classmethod
    def setUpClass(cls):
        if os.getenv('DEBUG'):
            logging.basicConfig(level=logging.DEBUG)


    def tearDown(self):
        """Tear down test fixtures, if any."""

    def get_match_obj(self) -> Type:
        return self.test_obj

    def test_new(self):
        """Test creation of a new hash."""

        hash = self.test_obj.hash("foobie bletch")
        logging.debug("Hash result: %s", hash)
        self.assertGreaterEqual(len(hash), self.alg_class.min_length, msg="Created hash is too short")
        # assertStartsWith
        self.assertRegex(hash, "^%s" % re.escape(self.alg_class.prefix), msg="Created hash doesn't start with prefix")

    ## # This is used by more than just AlgorithmSaltedMixin subclasses
    ## def test_match(self):
    ##     """Test creation of a new hash against an existing one with the same salt."""
    ##
    ##     if hasattr(self, 'foobie_bletch_hash'):
    ##         ...
    ##     else:
    ##         raise unittest.case.SkipTest

    def test_match(self):
        """
        Test creation of a new hash against an existing one (with the same salt
        where relevant).
        """

        # Potentially ignore object created by setUp()
        result = self.get_match_obj().hash("foobie bletch")
        self.assertEqual(result, self.foobie_bletch_hash, msg="Created hash doesn't match existing one")

    def test_recognise_hash(self):
        """Ensure that algorithms with a prefix can recognise a hash created by that algorithm."""

        if self.alg_class.prefix:
            result = hashpw.recognise_algorithm_by_hash(self.alg_class, self.foobie_bletch_hash)
            self.assertTrue(result, msg="Algorithm class %s can't recognise its hash '%s'" % (self.alg_class, self.foobie_bletch_hash))
        else:
            # Signal the fact that this algorithm's hash does not have a prefix.
            raise unittest.case.SkipTest


class AlgorithmUnsaltedMixin(AlgorithmGenericTests):
    def setUp(self):
        self.alg_class.init(self.alg_class)
        self.test_obj = self.alg_class()


class AlgorithmSaltedMixin(AlgorithmGenericTests):
    def setUp(self):
        self.alg_class.init(self.alg_class)
        self.test_obj = self.alg_class(None)

    def get_match_obj(self) -> Type:
        """Override the default object (which has a computed salt)."""

        return self.alg_class(self.foobie_bletch_hash)


class AlgorithmLongSaltedMixin(AlgorithmSaltedMixin):
    # override
    def setUp(self):
        self.alg_class.init(self.alg_class, long_salt=False)
        self.test_obj = self.alg_class(None)

    def test_long_match(self):
        """Test creation of a new hash against an existing one with the same long salt."""

        # Ignore object created by setUp()
        o = self.alg_class(self.foobie_bletch_long_salt_hash)
        result = o.hash("foobie bletch")
        self.assertEqual(result, self.foobie_bletch_long_salt_hash, msg="Created hash doesn't match existing one")


# == Algorithms ==
class TestMD5(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for MD5 algorithm."""

    foobie_bletch_hash = "$1$whM1oR8t$NSUPMGeDMxzvHmaQznskH0"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.MD5

    # This didn't work; wasn't called until mixin was put first
    ## def setUp(self):
    ##     """Set up test fixtures, if any."""
    ##     self.alg_class = hashpw.MD5
    ##     super().setUp()
    ## ... hack did work:   AlgorithmGenericTests.setUp(self)


class TestApacheMD5(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for ApacheMD5 algorithm."""

    foobie_bletch_hash = "$apr1$nvDkaCFk$W550C0URLLXNuFMMHF6hr1"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.ApacheMD5


class TestApacheSHA1(AlgorithmUnsaltedMixin, unittest.TestCase):
    """Tests for ApacheSHA1 algorithm."""

    foobie_bletch_hash = "{SHA}dVBgWFZK6.LyirGz2tMrahbDJC0="

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.ApacheSHA1


class TestBlowfish(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for Blowfish algorithm."""

    foobie_bletch_hash = "$2a$13$M8bmK/6noh6jR5c1k6.mouOWIPY7fiCvXJoz2m7XLNh6I7HcmmYiW"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.Blowfish


class TestSHA256(AlgorithmLongSaltedMixin, unittest.TestCase):
    """Tests for SHA256 algorithm."""

    # Note: this has a short salt; used for a test that ignores the salt generated by setUp()
    foobie_bletch_hash = "$5$/S3reJmb$7MsMDSq7rj6NmhX/UDaqEt7fr7qq9xOttBJ3pmrLfe6"
    foobie_bletch_long_salt_hash = "$5$EogawUIeAADv/FrL$qB4dby7OomkPFaEx4qRScoRAddrRRbIfW01kiG3oyzD"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.SHA256


class TestSHA512(AlgorithmLongSaltedMixin, unittest.TestCase):
    """Tests for SHA512 algorithm."""

    # Note: this has a short salt; used for a test that ignores the salt generated by setUp()
    foobie_bletch_hash = "$6$rOUMWIRL$gW/ONfnQr49m5ht4tLdBcstgcHF9jGaNrNckfTF41C3JJhMJM5aBudbU4EF.e1Q.KJ2kifIHDYaVojoNAvscW0"
    foobie_bletch_long_salt_hash = "$6$TiuxqBOJAACVvg5M$UV4xCoJZ2WYha1Fvzb1dr5M532QIdTmyjLuM5COBg3zsrkWex3ZAUJdTKIcWJJ7doSeJlolgRE430e88N/wLi/"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.SHA512


class TestMySqlSHA1(AlgorithmUnsaltedMixin, unittest.TestCase):
    """Tests for MySqlSHA1 algorithm."""

    foobie_bletch_hash = "*882BA6CC1DB13C1B715FAAAE945436F5CEBA5141"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.MySqlSHA1


class TestPBKDF2(AlgorithmLongSaltedMixin, unittest.TestCase):
    """Tests for PBKDF2 algorithm."""

    # Note: this has a short salt; used for a test that ignores the salt generated by setUp()
    foobie_bletch_hash = "pbkdf2_sha256$300000$MmoXWl7z$ajIqmiFyxv7GZy2vjOUA4cAhsQNVcpHXmv9lE0WyACs="
    foobie_bletch_long_salt_hash = "pbkdf2_sha256$300000$gDFTEPweqOTd4Yco$RiQCLFG53Rz6pFHigQFFM+DN9FHJGZzQ4+BiytgCods="

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.PBKDF2


class TestPhpass(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for Phpass algorithm."""

    foobie_bletch_hash = "$P$F0wq7Ab395fXOZmwF1qBW6JSop2Eh.0"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.Phpass


@unittest.skip("Algorithm unimplemented")
class TestPhpBB3(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for PhpBB3 algorithm."""

    foobie_bletch_hash = ""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.PhpBB3


class TestSSHA(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for SSHA algorithm."""

    foobie_bletch_hash = "{SSHA}maADmoZ/BucQdCVxzb8/bPqfmluLpxXo"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.SSHA


class TestBasicMD5(AlgorithmUnsaltedMixin, unittest.TestCase):
    """Tests for BasicMD5 algorithm."""

    foobie_bletch_hash = "5af53f1b0b70074e83fb7220c6629fb4"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.BasicMD5


class TestExtDes(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for ExtDes algorithm."""

    foobie_bletch_hash = "_yC6XeRxcbZnbFSh1Ccs"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.ExtDes


class TestCrypt(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for Crypt algorithm."""

    foobie_bletch_hash = "hhlu0X3HtjctQ"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.Crypt


class TestOldPassword(AlgorithmUnsaltedMixin, unittest.TestCase):
    """Tests for OldPassword algorithm."""

    foobie_bletch_hash = "15938e807de748cc"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.OldPassword


if __name__ == '__main__':
    unittest.main()
