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
        # Specifying an invalid salt causes one to be generated
        self.test_obj = self.alg_class(None)

    def get_match_obj(self) -> Type:
        """Override the default object (which has a computed salt)."""

        # Use a specific salt
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

class OptionalRoundsMixin(AlgorithmLongSaltedMixin):
    def test_basic_match(self):
        """Test creation of a new hash against an existing one with the same long salt."""

        # Ignore object created by setUp()
        o = self.alg_class(self.foobie_bletch_basic_hash)
        result = o.hash("foobie bletch")
        self.assertEqual(result, self.foobie_bletch_basic_hash, msg="Created hash doesn't match existing one")

    def test_long_basic_match(self):
        """Test creation of a new hash against an existing one with the same long salt."""

        # Ignore object created by setUp()
        o = self.alg_class(self.foobie_bletch_basic_long_salt_hash)
        result = o.hash("foobie bletch")
        self.assertEqual(result, self.foobie_bletch_basic_long_salt_hash, msg="Created hash doesn't match existing one")

class LazyPLVerifyMixin(AlgorithmGenericTests):
    """
    Handles classes that don't yet accept salts (__init__() param ignored)
    and pass through the verification.
    """

    def setUp(self):
        self.alg_class.init(self.alg_class)
        # Specifying an invalid salt causes one to be generated
        self.test_obj = self.alg_class(None)

    def test_match(self):
        """
        Test creation of a new hash against an existing one with the same salt.
        """

        # Potentially ignore object created by setUp()
        result = self.alg_class.verify("foobie bletch", self.foobie_bletch_hash)
        self.assertTrue(result, msg="Created hash doesn't match existing one")


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


class TestBCrypt(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for BCrypt algorithm."""

    foobie_bletch_hash = "$2b$13$LTBh67RRAABQEnmUJAIAAOWljYkQTzQYwT3EHiqU38GHtupHJj/F2"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.BCrypt


class TestBlowfish(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for Blowfish algorithm."""

    foobie_bletch_hash = "$2a$13$M8bmK/6noh6jR5c1k6.mouOWIPY7fiCvXJoz2m7XLNh6I7HcmmYiW"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.Blowfish


class TestSHA256(OptionalRoundsMixin, unittest.TestCase):
    """Tests for SHA256 algorithm."""

    # Note: only foobie_bletch_hash (short salt, rounds) is used by test_match();
    # others are used for tests that ignore the salt generated by setUp()
    foobie_bletch_hash = "$5$rounds=650000$hV1twEvL$k54.8ITSTRvDHoH/yrQqdy2qh.33GXjuSxIuq4eqNt4"
    foobie_bletch_long_salt_hash = "$5$rounds=650000$CvjoMNZWGBDmpcqh$as5FGzAyBy1NFwqtCgNGlEizrnty.jchKHZf/gy6YGB"
    foobie_bletch_basic_hash = "$5$/S3reJmb$7MsMDSq7rj6NmhX/UDaqEt7fr7qq9xOttBJ3pmrLfe6"
    foobie_bletch_basic_long_salt_hash = "$5$EogawUIeAADv/FrL$qB4dby7OomkPFaEx4qRScoRAddrRRbIfW01kiG3oyzD"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.SHA256


class TestSHA512(OptionalRoundsMixin, unittest.TestCase):
    """Tests for SHA512 algorithm."""

    # Note: only foobie_bletch_hash (short salt, rounds) is used by test_match();
    # others are used for tests that ignore the salt generated by setUp()
    foobie_bletch_hash = "$6$rounds=650000$yPr9zr8.$Fo6znbCRgLxyegSqMXfwWYtf4IIAi3TSUGQyjxCepbtFEPnkzCupyyuK5WWwoK5K7yUztF3tSROVYU6f2zYeS1"
    foobie_bletch_long_salt_hash = "$6$rounds=650000$SMnar0YBzrn/oEjG$iJYsd4LTGMxJ9/xia6xNUCtyEhCEN5Q7LD9fLSlslMXKPUHFZ36WxXijmOt1tatk.i1hS0uWAt0jGsEAdrjuG1"
    foobie_bletch_basic_hash = "$6$rOUMWIRL$gW/ONfnQr49m5ht4tLdBcstgcHF9jGaNrNckfTF41C3JJhMJM5aBudbU4EF.e1Q.KJ2kifIHDYaVojoNAvscW0"
    foobie_bletch_basic_long_salt_hash = "$6$TiuxqBOJAACVvg5M$UV4xCoJZ2WYha1Fvzb1dr5M532QIdTmyjLuM5COBg3zsrkWex3ZAUJdTKIcWJJ7doSeJlolgRE430e88N/wLi/"

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


## @unittest.skip("Algorithm unimplemented")
class TestPhpBB3(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for PhpBB3 algorithm."""

    foobie_bletch_hash = "$H$F61F3imUBtMs4RjQsiTuW/TGJ8U4ve/"

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


# MySQL
class TestBasicMD5(AlgorithmUnsaltedMixin, unittest.TestCase):
    """Tests for MySQL's MD5 algorithm."""

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


# MySQL
class TestOldPassword(AlgorithmUnsaltedMixin, unittest.TestCase):
    """Tests for OldPassword algorithm."""

    foobie_bletch_hash = "15938e807de748cc"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.OldPassword


# MySQL
class TestMySqlSHA1(AlgorithmUnsaltedMixin, unittest.TestCase):
    """Tests for MySqlSHA1 algorithm."""

    foobie_bletch_hash = "*882BA6CC1DB13C1B715FAAAE945436F5CEBA5141"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.MySqlSHA1


class TestLDAPv2SMD5(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for Crypt algorithm."""

    foobie_bletch_hash = "{SMD5}US3vYMX6Ib9q5qklKXVBStHHyC0="

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.LDAPv2SMD5


class TestLDAPv2SSHA256(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for  algorithm."""

    foobie_bletch_hash = "{SSHA256}1P2yehlGdiSHGedo4TmrtXVYfOadmJ4b8hoX7ukctM/dF0f6l5JxKw=="

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.LDAPv2SSHA256


class TestLDAPv2SSHA512(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for LDAPv2 SSHA512 algorithm."""

    foobie_bletch_hash = "{SSHA512}UzVf1pkQNeYMpj5SbmjSsGdDOActKhUYJWWIVjy5dR7gm7epCUsJSrC6cwsdM4C3W5cxgXZ7mDWmnykvRxVrmLn/lS10y5MH"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.LDAPv2SSHA512


class TestArgon2i(LazyPLVerifyMixin, unittest.TestCase):
    """Tests for Argon2i algorithm."""

    foobie_bletch_hash = "$argon2i$v=19$m=65536,t=3,p=4$rLU2hjCGEKJ0rnWOUeq9Nw$Fp2ein0paA+CqXdfTB1dZBnBymY5qa6S8dAH125s+zY"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.Argon2i


class TestArgon2d(LazyPLVerifyMixin, unittest.TestCase):
    """Tests for Argon2d algorithm."""

    foobie_bletch_hash = "$argon2d$v=19$m=65536,t=3,p=4$ovQ+h7C2tjbmvFdKKYVwDg$Kl3eI9ukDmO9azzWq1w+jyAerdNGQdhwX9IYVr3j2oo"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.Argon2d


class TestArgon2id(LazyPLVerifyMixin, unittest.TestCase):
    """Tests for Argon2id algorithm."""

    foobie_bletch_hash = "$argon2id$v=19$m=65536,t=3,p=4$AEAIwRjD2JtTKiUEoHRuDQ$UwWCcaK3MWoMY7dDVnLOVFv9BhZdhgjWcKvpqeweFqg"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.Argon2id


class TestDjangoBcryptSHA256(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for DjangoBcryptSHA256 algorithm."""

    foobie_bletch_hash = "bcrypt_sha256$$2b$12$6l6SZYrhUZVbSmEiI5x1Ae04/jwehlXR0rzBWZYWetXp7BVjQMH3i"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.DjangoBcryptSHA256


class TestDjangoArgon2(LazyPLVerifyMixin, unittest.TestCase):
    """Tests for DjangoArgon2 algorithm."""

    ## Not a typo; that thar's a Django additional prefix
    foobie_bletch_hash = "argon2$argon2i$v=19$m=65536,t=3,p=4$hBBiDMEYg3DO+R8DoNS6tw$fDY/gS+/voMl7pUrNzB5btS9MY76R/LcaaiuFJcst40"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.DjangoArgon2


class TestDjangoPBKDF2SHA1(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for DjangoPBKDF2SHA1 algorithm."""

    foobie_bletch_hash = "pbkdf2_sha1$800000$LGmLUuuxaTTF$J956dmetu8YuUzYtzr4KBvxuw4s="

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.DjangoPBKDF2SHA1


class TestGrubPBKDF2SHA512(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for Grub’s PBKDF2 SHA512 algorithm."""

    foobie_bletch_hash = "grub.pbkdf2.sha512.350000.7A26049484937B86CB81DCBF398962B54B17151FE09F7470A9B03977F093E49F03F1E516DA824D0903F43DAA6EB848137544F46EC4DB368C900FD45806886266.15A6FA049AFF22D5E16078934BBCD7533037839E8422DAF1E59CC136904D2B40E42C77CCBD03CF36F5E91241D1B78D186FC4F313882CF9D60F2042EE5CB6D634"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.GrubPBKDF2SHA512


class TestSCrypt(LazyPLVerifyMixin, unittest.TestCase):
    """Tests for SCrypt algorithm."""

    foobie_bletch_hash = "$scrypt$ln=12,r=8,p=1$Vwqh1Lr3fq8VQsj5H8MYQw$vLzdgG9GNnJa4hbYvDRqAXf/3pL2Q9Uaw/PdVECE9FA"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.SCrypt


class TestHTTPBasic(AlgorithmUnsaltedMixin, unittest.TestCase):
    """Tests for HTTPBasic algorithm."""

    foobie_bletch_hash = "Ym9iOmZvb2JpZSBibGV0Y2g="

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.HTTPBasic

    def setUp(self):
        self.alg_class.init(self.alg_class)
        # Specifying an invalid salt causes one to be generated
        self.test_obj = self.alg_class(username="bob")


class TestYesCrypt(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for YesCrypt algorithm."""

    foobie_bletch_hash = "$y$jBT/1$K1qLfl57Cm5s/cZbqgLM9.$.kDDFlXaLWzL2ebODporNLrWg4CvXkeunhxSNJAp.S0"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.YesCrypt


class TestYesCrypt7(AlgorithmSaltedMixin, unittest.TestCase):
    """Tests for YesCrypt algorithm."""

    foobie_bletch_hash = "$7$DU....0....ZPYwbM6PY155RiWHJ1SEU1$4wFVgFwEqIyWNwbpLRs75zR4CM27EbXDXP48vzw8qXA"

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.alg_class = hashpw.YesCrypt7


if __name__ == '__main__':
    unittest.main()
