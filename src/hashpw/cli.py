#! /usr/bin/python3
# hashpw -- prompts user for a password and prints the hash
#
__version__ = '2.2.0'
# Copyright: (C) 2013 Alastair Irvine <alastair@plug.org.au>
# Keywords: security passwd crypt
# Licence: This file is released under the GNU General Public License
#
usage = """Usage: hashpw [ -c | -C | -m | -a | -A | -b | -2 [ -l ] | -5 [ -l ] | -S | -p | -d [ -l ] | -M ] [ <salt> | -v [ -q ] <hash> ]
  -l  Force a salt of length 16 to be used with SHA-256 or SHA-512
  -e  Also prefix the hash with the scheme prefix used by "doveadm pw"
  -v  Verify instead of printing a hash
  -q  Don't print verification result (exit codes only; 0 = suceeded, 2 = failed)

Algorithm options:
  -m  MD5 (default)
  -c  crypt (DES), with a two character salt
  -x  Extended DES, with a nine character salt (FreeBSD 4.x and NetBSD only)
  -b  blowfish
  -a  Apache MD5
  -A  Apache SHA-1 (RFC 2307; can be used by OpenLDAP) (does not use a salt; INSECURE!!)
  -2  SHA-256
  -5  SHA-512 (Linux standard password hashing method)
  -S  SSHA (used by OpenLDAP)
  -o  MySQL OLD_PASSWORD() (does not use a salt; INSECURE!!)
  -p  MySQL v4.1+ PASSWORD() double SHA-1 (does not use a salt; INSECURE!!)
  -M  MySQL MD5() -- just hex encoding (does not use a salt; INSECURE!!)
  -d  PBKDF2 with Django prefix
  -P  Portable PHP password hashing framework, as used by WordPress
  -B  phpBB3: Same as -P except the hash starts with "$H$" instead of "$P$"
  -C  CRAM-MD5 (does not use a salt; INSECURE!!)
  -D  DIGEST-MD5 (requires username)
  -s  SCRAM-SHA-1 (RFC 5802; see https://en.wikipedia.org/wiki/Salted_Challenge_Response_Authentication_Mechanism)
"""
#
# See http://forum.insidepro.com/viewtopic.php?t=8225 for more algorithms
#
#
# Licence details:
#     This program is free software; you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation; either version 2 of the License, or (at
#     your option) any later version.
#
#     See https://www.gnu.org/licenses/gpl-3.0.html for more information.
#
#     You can find the complete text of the GPLv2 in the file
#     /usr/share/common-licenses/GPL-3 on Debian systems.
#     Or see the file LICENSE in the same directory as this program.

import sys
import base64
import binascii
import random
import getpass
import struct
import crypt
import getopt
import hashlib

import passlib.hash
import passlib.utils.binary
import passlib.utils


program_name = "hashpw"

EXIT_OK = 0
EXIT_CMDLINE_BAD = 1
EXIT_VERIFY_FAILED = 2
EXIT_VERIFY_PARTIAL_HASH = 3
EXIT_VERIFY_NO_SALT = 4
EXIT_PASSWORD_MISMATCH = 5
EXIT_SHORT_SALT = 7
EXIT_SALT_PREFIX = 8
EXIT_BAD_ALG = 10
EXIT_MISSING_HANDLER = 11
EXIT_MULTIPLE_MODES = 13
EXIT_MISSING_MODE = 14

DEFAULT_MODE = "md5"

# Defaults that can be modified on the command line
settings = {'verify': False, 'quiet': False}
mode = None
alg_class = None    # this will be determined by scanning properties of the classes

# == general-purpose functions ==
def barf(msg, exitstatus):
    "Shows an error message to stderr and exits with a given value"
    print(program_name + ":", msg, file=sys.stderr)
    sys.exit(exitstatus)


def help():
    print(usage)


# *** Processing code ***
class ShortSaltException(Exception):
    def __init__(self, msg="salt is too short"):
        Exception.__init__(self, msg)



class SaltPrefixException(Exception):
    pass



class BadAlgException(Exception):
    pass



class Algorithm(object):
    supports_salt = False


    @staticmethod
    def init(c):
        """Called by the top level, regardless of whether the class is
        instantiated."""
        pass


    @staticmethod
    def final_prep(c):
        """Called by the constructor, i.e. only if the algorithm class is
        actually going to be used.  Initialises things in the class that are
        used by various static helper methods.

        Designed to be overridden.  Subclasses should call this method on their
        superclass, but beware that if that superclass inherits final_prep(), its
        class object is still where attributes will be set."""
        ## print "Algorithm.final_prep()..."
        pass


    def __init__(self):
        self.final_prep(self.__class__)


    @staticmethod
    def recognise_full(c, s):
        """Returns whether or not @p s matches the encoding format of algorithm @p c"""
        return len(s) >= c.min_length and s[:len(c.prefix)] == c.prefix


    def hash(self, plaintext):
        """Returns an encoded hash"""



class SaltedAlgorithm(Algorithm):
    """Stores a salt, which includes the prefix."""

    supports_salt = True
    r = random.SystemRandom()


    @staticmethod
    def init(c):
        c.comp_len = len(c.prefix) + c.salt_length + len(c.suffix)


    def __init__(self, salt):
        # Note that unlike SaltedAlgorithm, Algorithm's constructor doesn't take
        # an argument
        super().__init__()

        if salt:
            self.salt = self.extract_salt(self, salt)
        else:
            self.salt = self.generate_salt(self)


    @staticmethod
    def recognise_full(c, s):
        """Returns whether or not @p s matches this algorithm's encoding format"""
        return len(s) >= c.min_length and c.recognise_salt_internal(c, s)


    @staticmethod
    def recognise_salt_internal(c, s):
        """Returns whether or not @p s matches the leading part of this
        algorithm's encoding format"""
        return s[:len(c.prefix)] == c.prefix


    @staticmethod
    def recognise_salt(c, s):
        """Returns whether or not @p s matches the leading part of this
        algorithm's encoding format and is long enough to contain a salt."""
        return s[:len(c.prefix)] == c.prefix and len(s) >= c.comp_len


    @staticmethod
    def generate_salt(c):
        """Calculate an encoded salt string, including prefix, for algorithm @p c .
        Note that blowfish supports up to a 22-character salt, but only 16 is provided
        by this method."""

        # make a salt consisting of 96 bits of random data, packed into a
        # string, encoded using a variant of base-64 encoding and surrounded
        # by the correct markers
        rand_bits = struct.pack('<QQ', c.r.getrandbits(48), c.r.getrandbits(48))[:12]
        salt = c.prefix + base64encode(rand_bits)[:c.salt_length] + c.suffix

        return salt


    @staticmethod
    def generate_raw_salt(c):
        """Calculate a base64-encoded salt string."""

        # make a salt consisting of 96 bits of random data, packed into a
        # string, encoded using a variant of base-64 encoding
        rand_bits = struct.pack('<QQ', c.r.getrandbits(48), c.r.getrandbits(48))[:12]
        salt = base64encode(rand_bits)

        return salt


    @staticmethod
    def extract_salt(c, s):
        """Takes the prefix-plus-salt from the argument."""
        c.check_salt(c, s)

        return s[:c.comp_len]


    @staticmethod
    def check_salt(c, salt):
        """Checks that the supplied salt conforms to the required format of the
        current mode."""
        # TO-DO: warn if the supplied salt is too long (don't warn on whole password)
        if len(salt) < c.comp_len:
            raise ShortSaltException()
        elif not c.recognise_salt_internal(c, salt):
            raise SaltPrefixException("supplied salt should start with " + c.prefix)


    def hash(self, plaintext):
        """Returns an encoded hash"""
        return_value = crypt.crypt(plaintext, self.salt)

        # Check that the hash starts with the salt; otherwise, crypt(3) might
        # not understand the algorithm implied by the salt format
        if return_value[:self.comp_len] != self.salt:
            raise BadAlgException(mode + " hashing does not appear to be supported on this platform")

        return return_value



class BinarySaltedAlgorithm(SaltedAlgorithm):
    """For algorithms that use binary salts."""

    @staticmethod
    def init(c):
        """Ensure that check_salt() checks the length of the whole hash."""
        c.comp_len = c.min_length


    @staticmethod
    def generate_salt(c):
        """Calculates a binary salt string for algorithm @p c ."""

        # make a salt consisting of 96 bits of random data and save the
        # required number of bytes worth
        rand_bits = struct.pack('<QQ', c.r.getrandbits(48), c.r.getrandbits(48))[:12]
        salt = rand_bits[:c.salt_length]

        return salt


    @staticmethod
    def extract_salt(c, hash):
        """Takes the prefix-plus-salt from the argument and if valid, decodes it."""
        c.check_salt(c, hash)

        # decode everything after the prefix
        bits = base64decode(hash[len(c.prefix):])

        # return everything after the digest part of the decoded bits
        return bits[c.digest_length:]


class PLSaltedAlgorithm(SaltedAlgorithm):
    """
    Specific class for algorithms that use passlib.

    Class is required to set `self.hasher` in `__init__()`. 
    """

    def hash(self, plaintext):
        """
        Make a hash using 'passlib' (unlike parent that uses 'crypt').

        Doesn't use PasswordHash.hash_password() because that generates its
        own salt.  Instead, use the internal function that is used when
        PasswordHash.portable_hashes is true.
        """

        return self.hasher.hash(plaintext)



class Crypt(SaltedAlgorithm):
    name = "crypt"
    option = "c"
    prefix = ""
    suffix = ""
    min_length = 13
    salt_length = 2


    @staticmethod
    def recognise_full(c, s):
        return len(s) == c.min_length



class ExtDes(SaltedAlgorithm):
    name = "ext-des"
    option = "x"
    prefix = "_"
    suffix = ""
    min_length = 20
    salt_length = 8


    ## @staticmethod
    ## def recognise_salt(c, s):
    ##     return False



class MD5(SaltedAlgorithm):
    name = "md5"
    option = "x"
    prefix = "$1$"
    suffix = ""
    min_length = 34
    salt_length = 8



class ApacheMD5(PLSaltedAlgorithm):
    name = "apache-md5"
    option = "a"
    prefix = "$apr1$"
    suffix = ""
    min_length = 37
    salt_length = 8


    def __init__(self, salt):
        super().__init__(salt)

        self.hasher = passlib.hash.apr_md5_crypt.using(salt=self.salt[6:])



class ApacheSHA1(Algorithm):
    name = "apache-sha-1"
    option = "A"
    prefix = "{SHA}"
    suffix = ""
    min_length = 33


    def hash(self, plaintext):
        input_byte_str = plaintext.encode("UTF-8")
        round_output = hashlib.sha1(input_byte_str).digest()
        return self.prefix + base64encode(round_output)



class Blowfish(SaltedAlgorithm):
    """See https://pypi.org/project/py-bcrypt/"""
    name = "blowfish"
    option = "b"
    prefix = "$2a$"
    extra_prefix = "{BLF-CRYPT}"
    suffix = ""
    min_length = 57
    salt_length = 16


    @staticmethod
    def final_prep(c):
        """[Override]"""
        c.rounds=13

        # Pass it up the hierarchy
        SaltedAlgorithm.final_prep(c)

        global bcrypt
        import bcrypt


    ## def __init__(self, salt):
    ##     super().__init__(salt)


    def hash(self, plaintext):
        return bcrypt.hashpw(plaintext, self.salt)


    @staticmethod
    def generate_salt(c):
        """Calculates an encoded salt string, including prefix, for this algorithm."""
        return bcrypt.gensalt(log_rounds=c.rounds)



class SHA256(SaltedAlgorithm):
    name = "sha-256"
    option = "2"
    prefix = "$5$"
    extra_prefix = "{SHA256-CRYPT}"
    suffix = "$"
    min_length = 55


    @staticmethod
    def init(c):
        if settings.get('long_salt'):
            c.salt_length = 16
        else:
            c.salt_length = 8
        SaltedAlgorithm.init(c)



class SHA512(SaltedAlgorithm):
    name = "sha-512"
    option = "5"
    prefix = "$6$"
    extra_prefix = "{SHA512-CRYPT}"
    suffix = "$"
    min_length = 98


    @staticmethod
    def init(c):
        if settings.get('long_salt'):
            c.salt_length = 16
        else:
            c.salt_length = 8
        SaltedAlgorithm.init(c)



class MySqlSHA1(Algorithm):
    name = "mysql-sha-1"
    option = "p"
    prefix = "*"
    suffix = ""
    min_length = 41


    def hash(self, plaintext):
        input_byte_str = plaintext.encode("UTF-8")
        first_round_output = hashlib.sha1(input_byte_str).digest()
        second_round_output = hashlib.sha1(first_round_output).digest()
        output_byte_str = binascii.hexlify(second_round_output)
        return "*" + output_byte_str.decode('ascii').upper()


class OldPassword(Algorithm):
    """Pre-v4.1 MySQL, and also newer with the 'old-passwords' setting on

    http://djangosnippets.org/snippets/1508/"""
    name = "old-password"
    option = "o"
    prefix = ""
    suffix = ""
    min_length = 16


    @staticmethod
    def final_prep(c):
        """[Override]"""
        # Pass it up the hierarchy
        Algorithm.final_prep(Algorithm)

        global mysql_hash_password
        from hashpw.contrib.tback import mysql_hash_password


    def recognise(self, s):
        return False


    def hash(self, plaintext):
        return mysql_hash_password(plaintext)



class BasicMD5(Algorithm):
    name = "basic-md5"
    option = "M"
    prefix = ""
    extra_prefix = "{PLAIN-MD5}"
    suffix = ""
    min_length = 32


    def hash(self, plaintext):
        input_byte_str = plaintext.encode("UTF-8")
        first_round_output = hashlib.md5(input_byte_str).digest()
        output_byte_str = binascii.hexlify(first_round_output)
        return output_byte_str.decode('ascii')



class Phpass(PLSaltedAlgorithm):
    """https://github.com/exavolt/python-phpass
    e.g. portable (safe MD5): $P$Bnvt73R2AZ9NwrY8agFUwI1YUYQEW5/
         Blowfish: $2a$08$iys2/e7hwWyX2YbWtjCyY.tmGy2Y.mGlV9KwIAi9AUPgBuc9rdJVe"""

    name = "phpass"
    option = "P"
    prefix = "$P$"
    suffix = ""
    min_length = 34
    salt_length = 9  # includes the round count


    @staticmethod
    def final_prep(c):
        """[Override]"""
        c.rounds=17
        ## c.round_id_chars = "23456789ABCDEFGHIJKLMNOP"
        ## c.round_id_chars = "789ABCDEFGHIJKLMNOPQRSTU"

        # Pass it up the hierarchy
        SaltedAlgorithm.final_prep(c)


    def __init__(self, salt):
        super().__init__(salt)

        self.hasher = passlib.hash.phpass.using(salt=self.salt[4:], rounds=self.rounds)


    @staticmethod
    def generate_salt(c):
        """Calculates an encoded salt string, including prefix, for this algorithm."""
        salt_chars = SaltedAlgorithm.generate_raw_salt(SaltedAlgorithm)[0:8]
        round_char = passlib.utils.binary.h64.encode_int6(c.rounds).decode("ascii")
        s = c.prefix + round_char + salt_chars
        return s



class PhpBB3(Phpass):
    name = "phpBB3"
    option = "B"
    prefix = "$H$"
    suffix = ""


    def hash(self, plaintext):
        raise BadAlgException(self.name + " not implemented")



class SSHA(BinarySaltedAlgorithm):
    name = "ssha"
    option = "S"
    prefix = "{SSHA}"
    suffix = ""
    min_length = 38
    salt_length = 4
    digest_length = 20


    def hash(self, plaintext):
        input_byte_str = plaintext.encode("UTF-8")
        context = hashlib.sha1(input_byte_str )
        context.update(self.salt)
        output_byte_str = context.digest()
        return self.prefix + base64encode(output_byte_str + self.salt)



# *** FUNCTIONS ***
def base64encode(bits):
    """
    Returns a base64-encoded string using the standard password alphabet
    instead of the default or url-safe ones.
    """
    return base64.b64encode(bits, b'./').decode('ascii')


def base64decode(hash):
    """Extracts bits from a base64-encoded string using the standard password alphabet
    instead of the default or url-safe ones."""
    return base64.b64decode(hash, b'./')


def recognise_algorithm_by_hash(algorithm, s):
    return algorithm.recognise_full(algorithm, s)


def recognise_algorithm_by_salt(algorithm, s):
    if algorithm.supports_salt:
        return algorithm.recognise_salt(algorithm, s)
    else:
        return algorithm.recognise_full(algorithm, s)
        ## return False


def create_hasher(alg_class, salt, settings):
    """
    Create an object of the algorithm's class, warning if a salt was
    supplied by the algorithm doesn't support it.
    """

    if alg_class.supports_salt:
        return alg_class(salt)
    else:
        if salt and not settings['verify']:
            print("ignoring salt", file=sys.stderr)
        return alg_class()


def make_hash(hasher, s: str):
    ## plaintext = s.encode("UTF-8")

    return hasher.hash(s)


# *** MAINLINE ***
# == initialisation ==
# Algorithms with longer prefixes need to appear earlier in this list
algorithms = (MD5, ApacheMD5, ApacheSHA1, Blowfish, SHA256, SHA512, MySqlSHA1, Phpass, PhpBB3, SSHA, BasicMD5, ExtDes, Crypt, OldPassword)
## PBKDF2, 
short_to_long = {}
opt_string = ""
alg_names = []
for a in algorithms:
    short_to_long[a.option] = a.name
    # build the option sequences
    opt_string += a.option
    alg_names.append(a.name)


def main():
    # == Command-line parsing ==
    # -- defaults --
    # See globals above
    global settings
    global mode
    global alg_class


    # -- option handling --
    try:
        (opts, args) = getopt.getopt(sys.argv[1:], opt_string + "lvqh", ['help'] + alg_names)
    except getopt.GetoptError as e:
        print(program_name + ":", e, file=sys.stderr)
        sys.exit(EXIT_CMDLINE_BAD)

    if ("--help",'') in opts or ("-h",'') in opts:
        help()
        sys.exit(EXIT_OK)

    for optpair in opts:
        if len(optpair[0]) == 2 and optpair[0][0] == "-":
            # short option
            if optpair[0][1] in short_to_long:
                mode = short_to_long[optpair[0][1]]
            elif optpair[0] == "-l":
                settings['long_salt'] = True
            elif optpair[0] == "-v":
                settings['verify'] = True
            elif optpair[0] == "-q":
                settings['quiet'] = True
        else:
            # long option
            if optpair[0][2:] in list(short_to_long.values()):
                if mode:
                    barf("Multiple mode options are not allowed", EXIT_MULTIPLE_MODES)
                mode = optpair[0][2:]

    # -- pre-preparation --
    if settings['verify']:
        recognise_algorithm = recognise_algorithm_by_hash
    else:
        recognise_algorithm = recognise_algorithm_by_salt

    # have to do this after option handling but before algorithm recognition
    for a in algorithms:
        a.init(a)
    alg_class = None

    # -- argument handling --
    # handle a salt if one was supplied
    if len(args) > 0:
        salt = args[0]
        # try to guess the algorithm
        if not mode:
            for a in algorithms:
                if recognise_algorithm(a, salt):
                    mode = a.name
                    alg_class = a
                    break
    else:
        if settings['verify']:
            barf("Verify mode cannot be used if no salt is supplied", EXIT_VERIFY_NO_SALT)
        salt = None

    # == preparation ==
    if not mode:
        mode = DEFAULT_MODE

    if not alg_class:
        # determine algorithm
        for a in algorithms:
            if a.name == mode:
                alg_class = a
                break
        else:
            barf("mode " + mode + " not found", EXIT_MISSING_MODE)

    # == sanity checking ==
    if settings['verify'] and not recognise_algorithm_by_hash(alg_class, salt):
        barf("Verify mode requires a full hash to check against", EXIT_VERIFY_PARTIAL_HASH)

    # == processing ==
    try:
        # get two password(s)
        pw1 = getpass.getpass()
        if not settings['verify']:
            pw2 = getpass.getpass("Re-enter password: ")
            # compare them and if they don't match, report an error
            if pw1 != pw2:
                barf("Passwords do not match", EXIT_PASSWORD_MISMATCH)
            else:
                if pw1 == "":
                    print(program_name + ":", "warning: password is blank!!", file=sys.stderr)
    except KeyboardInterrupt:
        print("^C", file=sys.stderr)
        sys.exit(EXIT_OK)

    # hash password
    try:
        # Don't call this hasher
        hasher = create_hasher(alg_class, salt, settings)

        if not settings['verify']:
            print(make_hash(hasher, pw1))   ## .decode('ascii'))
        else:
            # verify mode (would have barfed by now if there was no salt)
            if make_hash(hasher, pw1) == salt:
                if not settings['quiet']: print("Verify suceeded.")
            else:
                if not settings['quiet']: print("Verify failed!")
                sys.exit(EXIT_VERIFY_FAILED)       # don't re-use mismatch code
    except ShortSaltException as e:
        barf(e, EXIT_SHORT_SALT)
    except SaltPrefixException as e:
        barf(e, EXIT_SALT_PREFIX)
    except BadAlgException as e:
        barf(e, EXIT_BAD_ALG)
    except ImportError as e:
        barf("Cannot find required algorithm handler: %s" % (e,), EXIT_MISSING_HANDLER)
