#! /usr/bin/python
# hashpw -- prompts user for a password and prints the hash
#
# Version: 2.2.0
# Copyright: (C) 2013 Alastair Irvine <alastair@plug.org.au>
# Keywords: security passwd crypt
# Licence: This file is released under the GNU General Public License
#
usage = """Usage: hashpw [ -c | -C | -m | -a | -A | -b | -2 [ -l ] | -5 [ -l ] | -S | -p | -M ] [ <salt> | -v [ -q ] <hash> ]
  -l  Force a salt of length 16 to be used with SHA-256 or SHA-512
  -e  Also prefix the hash with the scheme prefix used by "doveadm pw"
  -v  Verify instead of printing a hash
  -q  Don't print verification result (exit codes only; 0 = suceeded, 2 = failed)

Algorithm options:
  -m  MD5 (default)
  -c  crypt (DES), with a two character salt
  -x  Extended DES, with a nine character salt (FreeBSD 4.x and NetBSD only)
  -b  blowfish (OpenBSD only)
  -a  Apache MD5*
  -A  Apache SHA-1 (RFC 2307; can be used by OpenLDAP) (does not use a salt; INSECURE!!)
  -2  SHA-256
  -5  SHA-512 (Linux standard password hashing method)
  -S  SSHA (used by OpenLDAP)
  -o  MySQL OLD_PASSWORD() custom algorithm*** (does not use a salt; INSECURE!!)
  -p  MySQL v4.1+ PASSWORD() double SHA-1 (does not use a salt; INSECURE!!)
  -M  MySQL MD5() -- just hex encoding (does not use a salt; INSECURE!!)
  -P  Portable PHP password hashing framework, as used by WordPress
  -B  phpBB3: Same as -P except the hash starts with "$H$" instead of "$P$"
  -C  CRAM-MD5 (does not use a salt; INSECURE!!)
  -D  DIGEST-MD5 (requires username)
  -s  SCRAM-SHA-1 (RFC 5802; see https://en.wikipedia.org/wiki/Salted_Challenge_Response_Authentication_Mechanism)
* requires 'pyapache' from https://github.com/mcrute/pyapache
*** requires the script from http://djangosnippets.org/snippets/1508"""
#
# Requires Python 2.4 for random.SystemRandom
# Unless using Python 2.5 or later, requires http://pypi.python.org/pypi/hashlib (built into Python 2.5)
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
#     See http://www.gnu.org/licenses/gpl-2.0.html for more information.
#
#     You can find the complete text of the GPLv2 in the file
#     /usr/share/common-licenses/GPL-2 on Debian systems.
#     Or see the file COPYING in the same directory as this program.
#
#
# TO-DO:
#   + if the prefix matches but the salt is too short, report an error
#   + other options for bcrypt (Phpass) using one of the following:
#       - http://www.mindrot.org/projects/py-bcrypt/
#       - http://packages.python.org/passlib/
#   + support Drupal 7's SHA-512-based secure hash (hash type identifier = "$S$")
#   + support Password-Based Key Derivation Function 2 <https://en.wikipedia.org/wiki/PBKDF2>
#       - http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf 
#       - $pdkdf2$ (SHA-1)
#       - $pdkdf2-sha256$ (SHA-256)
#       - $pdkdf2-sha512$ (SHA-512)
#   + support phpBB3: copy -P (hash type identifier = "$H$")
#   + handle http://en.wikipedia.org/wiki/Crypt_(Unix)#Blowfish-based_scheme
#   + convert to a module
#   + for Blowfish, recognise "$2y$" and provide an option to use it.
#       - see CRYPT_BLOWFISH comments at http://www.php.net/manual/en/function.crypt.php
#   + support scrypt <https://en.wikipedia.org/wiki/Scrypt>
#   + option to generate/recognise simple hashes (e.g. BasicMD5, OldPassword) with prefixes
#   + accept password on standard input (without confirmation)
#   + activate settings['long_salt'] if a long salt (or hash with long salt) is provided on the command line
#   + implement -C
#   + implement -D
#   + implement -e
#   + support "doveadm pw" encoding scheme suffixes (.b64, .base64 and .hex); see 
#     http://wiki2.dovecot.org/Authentication/PasswordSchemes
#   + support Argon2i password hashing algorithm: https://wiki.php.net/rfc/argon2_password_hash

import sys
import base64
import binascii
import random
import getpass
import struct
import crypt
import getopt
import hashlib

program_name = "hashpw"
DEFAULT_MODE = "md5"

# Defaults that can be modified on the command line
settings = {'verify': False, 'quiet': False}
mode = None
alg_class = None    # this will be determined by scanning properties of the classes

# == general-purpose functions ==
def barf(msg, exitstatus):
    "Shows an error message to stderr and exits with a given value"
    print >> sys.stderr, program_name + ":", msg
    sys.exit(exitstatus)


def help():
    print usage


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
        super(SaltedAlgorithm,self).__init__()

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
    prefix = ""
    suffix = ""
    min_length = 0
    salt_length = 9


    @staticmethod
    def recognise_salt(c, s):
        return False



class MD5(SaltedAlgorithm):
    name = "md5"
    option = "x"
    prefix = "$1$"
    suffix = ""
    min_length = 34
    salt_length = 8



class ApacheMD5(SaltedAlgorithm):
    name = "apache-md5"
    option = "a"
    prefix = "$apr1$"
    suffix = ""
    min_length = 37
    salt_length = 8


    def hash(self, plaintext):
        # http://mike.crute.org/blog/2008/07/12/python-apache-library-plus-htaccess/
        import pyapache.md5
        return pyapache.md5.generate_md5(plaintext, self.salt[6:14])



class ApacheSHA1(Algorithm):
    name = "apache-sha-1"
    option = "A"
    prefix = "{SHA}"
    suffix = ""
    min_length = 33


    def hash(self, plaintext):
        return self.prefix + base64encode(hashlib.sha1(plaintext).digest())



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
        SaltedAlgorithm.final_prep(SaltedAlgorithm)

        global bcrypt
        import bcrypt


    ## def __init__(self, salt):
    ##     super(Phpass,self).__init__(salt)


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
        return "*" + binascii.hexlify(hashlib.sha1(hashlib.sha1(plaintext).digest()).digest()).upper()


class OldPassword(Algorithm):
    """Pre-v4.1 MySQL, and also newer with the INSERTNAMEHERE setting on
    
    http://djangosnippets.org/snippets/1508/"""
    name = "old-password"
    option = "o"
    prefix = ""
    suffix = ""
    min_length = 16


    def recognise(self, s):
        return False


    def hash(self, plaintext):
        import old_password
        return old_password.mysql_hash_password(plaintext)



class BasicMD5(Algorithm):
    name = "basic-md5"
    option = "M"
    prefix = ""
    extra_prefix = "{PLAIN-MD5}"
    suffix = ""
    min_length = 32


    def hash(self, plaintext):
        return binascii.hexlify(hashlib.md5(plaintext).digest())



class Phpass(SaltedAlgorithm):
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
        SaltedAlgorithm.final_prep(SaltedAlgorithm)

        global passlib
        import passlib.hash
        import passlib.utils.binary


    def __init__(self, salt):
        super(Phpass,self).__init__(salt)

        self.hasher = passlib.hash.phpass.using(salt=self.salt[4:], rounds=self.rounds)


    def hash(self, plaintext):
        """Doesn't use PasswordHash.hash_password() because that generates its
        own salt.  Instead, use the internal function that is used when
        PasswordHash.portable_hashes is true."""
        
        return self.hasher.hash(plaintext)


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
        context = hashlib.sha1(plaintext)
        context.update(self.salt)
        return self.prefix + base64encode(context.digest()+self.salt)



def base64encode(bits):
    """Returns a base64-encoded string using the standard password alphabet
    instead of the default or url-safe ones."""
    return base64.b64encode(bits, './')


def base64decode(hash):
    """Extracts bits from a base64-encoded string using the standard password alphabet
    instead of the default or url-safe ones."""
    return base64.b64decode(hash, './')


def recognise_algorithm_by_hash(algorithm, s):
    return algorithm.recognise_full(algorithm, s)


def recognise_algorithm_by_salt(algorithm, s):
    if algorithm.supports_salt:
        return algorithm.recognise_salt(algorithm, s)
    else:
        return algorithm.recognise_full(algorithm, s)
        ## return False



# *** MAINLINE ***
# == initialisation ==
algorithms = (MD5, ApacheMD5, ApacheSHA1, Blowfish, SHA256, SHA512, MySqlSHA1, Phpass, PhpBB3, SSHA, BasicMD5, ExtDes, Crypt, OldPassword)
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
    except getopt.GetoptError, e:
        print >> sys.stderr, program_name + ":", e
        sys.exit(1)

    if ("--help",'') in opts or ("-h",'') in opts:
        help()
        sys.exit(0)

    for optpair in opts:
        if len(optpair[0]) == 2 and optpair[0][0] == "-":
            # short option
            if short_to_long.has_key(optpair[0][1]):
                mode = short_to_long[optpair[0][1]]
            elif optpair[0] == "-l":
                settings['long_salt'] = True
            elif optpair[0] == "-v":
                settings['verify'] = True
            elif optpair[0] == "-q":
                settings['quiet'] = True
        else:
            # long option
            if optpair[0][2:] in short_to_long.values():
                if mode:
                    barf("Multiple mode options are not allowed", 13)
                mode = optpair[0][2:]

    # -- pre-preparation --
    if settings['verify']:
        recognise_algorithm = recognise_algorithm_by_hash
    else:
        recognise_algorithm = recognise_algorithm_by_salt

    # have to do this after option handling but before algorithm recognition
    for a in algorithms:
        a.init(a)

    # -- argument handling --
    # handle a salt if one was supplied
    if len(args) > 0:
        salt = args[0]
        # try to guess the algorithm
        if not mode:
            for a in algorithms:
                if recognise_algorithm(a, salt):
                    mode = a.name
                    break
    else:
        if settings['verify']:
            barf("Verify mode cannot be used if no salt is supplied", 4)
        salt = None

    # == preparation ==
    if not mode:
        mode = DEFAULT_MODE

    # determine algorithm
    alg_class = None
    for a in algorithms:
        if a.name == mode:
            alg_class = a
    if not a:
        barf("mode " + mode + " not found", 14)

    # == sanity checking ==
    if settings['verify'] and not recognise_algorithm_by_hash(alg_class, salt):
        barf("Verify mode requires a full hash to check against", 3)

    # == processing ==
    try:
        # get two password(s)
        pw1 = getpass.getpass()
        if not settings['verify']:
            pw2 = getpass.getpass("Re-enter password: ")
            # compare them and if they don't match, report an error
            if pw1 != pw2:
                barf("Passwords do not match", 5)
            else:
                if pw1 == "":
                    print >> sys.stderr, program_name + ":", "warning: password is blank!!"
    except KeyboardInterrupt:
        print >> sys.stderr, "^C"
        sys.exit(0)

    # hash password
    try:
        if alg_class.supports_salt:
            hasher = alg_class(salt)
        else:
            if salt and not settings['verify']: print >> sys.stderr, "ignoring salt"
            hasher = alg_class()

        if not settings['verify']:
            print hasher.hash(pw1)
        else:
            # verify mode (would have barfed by now if there was no salt)
            if hasher.hash(pw1) == salt:
                if not settings['quiet']: print("Verify suceeded.")
            else:
                if not settings['quiet']: print("Verify failed!")
                exit(2)       # don't re-use mismatch code
    except ShortSaltException, e:
        barf(e, 7)
    except SaltPrefixException, e:
        barf(e, 8)
    except BadAlgException, e:
        barf(e, 10)
    except ImportError, e:
        barf("Cannot find required algorithm handler: %s" % (e,), 11)

