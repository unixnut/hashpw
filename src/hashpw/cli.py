#! /usr/bin/python3
# hashpw -- prompts user for a password and prints the hash
#
# Copyright: (C) 2013 Alastair Irvine <alastair@plug.org.au>
# Keywords: security passwd crypt
# Licence: This file is released under the GNU General Public License
#
usage = """Usage: hashpw [ -e ] [ -c | -C | -m | -a | -A | -b | -2 [ -l ] | -5 [ -l ] | -S | -p | -d [ -l ] | -M ] [ <salt> | -v [ -q ] <hash> ]
  -l  Force a salt of length 16 to be used with PBKDF2, SHA-256 or SHA-512
  -e  Also prefix the hash with the scheme prefix used by "doveadm pw"
  -v  Verify instead of printing a hash
  -V  Show program version information
  -I  Show information about the selected algorithm instead of printing a hash
  -q  Don't print verification result (exit codes only; 0 = suceeded, 2 = failed)
  -r <rounds>  Set round count
  -R <rounds>  Set logarithmic round count
  -u <username>

Algorithm options:
  -m  MD5 (default)
  -c  crypt (DES), with a two character salt
  -x  Extended DES, with a nine character salt (FreeBSD 4.x and NetBSD only)
  -O  blowfish A.K.A. BCrypt (older "$2a$" prefix)
  -b  blowfish A.K.A. BCrypt (standard "$2b$" prefix)
  -y  blowfish A.K.A. BCrypt (variant "$2y$" prefix used by BSD)
  -a  Apache MD5
  -A  Apache SHA-1 (RFC 2307; can be used by OpenLDAP) (does not use a salt; INSECURE!!)
  -z  Argon2
  -s  BCrypt+SHA256
  -f  Fairly Secure Hashed Password
  -g  Grub’s PBKDF2 Hash
  -2  SHA-256
  -5  SHA-512 (Linux standard password hashing method)
  -L  LDAPv2 salted MD5 digest
  -S  LDAPv2 salted SHA1 digest a.k.a. SSHA (used by OpenLDAP)
  --ssha256 LDAPv2 salted SHA256 digest
  --ssha512 LDAPv2 salted SHA512 digest
  -o  MySQL OLD_PASSWORD() (does not use a salt; INSECURE!!)
  -p  MySQL v4.1+ PASSWORD() double SHA-1 (does not use a salt; INSECURE!!)
  -M  MySQL MD5() -- just hex encoding (does not use a salt; INSECURE!!)
  -d  PBKDF2 with Django prefix
  -P  Portable PHP password hashing framework, as used by WordPress
  -B  phpBB3: Same as -P except the hash starts with "$H$" instead of "$P$"
  -C  CRAM-MD5 (does not use a salt; INSECURE!!)
  -D  DIGEST-MD5 (requires username)
  -1  SCRAM-SHA-1 (RFC 5802; see https://en.wikipedia.org/wiki/Salted_Challenge_Response_Authentication_Mechanism)
  --pbkdf2-sha1
  --pbkdf2-sha256
  --pbkdf2-sha512
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
import collections
import getopt
import getpass
import logging
import math

import hashpw       # Top-level module
from . import errors


# *** DEFINITIONS ***
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
EXIT_ROUNDS = 15
EXIT_BAD_OPTION = 16

DEFAULT_MODE = "md5"

# Defaults that can be modified on the command line
settings = collections.defaultdict(bool)
settings.update({'verify': False, 'quiet': False})
mode = None
alg_class = None    # this will be determined by scanning properties of the classes


# *** FUNCTIONS ***
# == general-purpose functions ==
def barf(msg, exitstatus):
    "Shows an error message to stderr and exits with a given value"
    print(program_name + ": ERROR:", msg, file=sys.stderr)
    sys.exit(exitstatus)


def help():
    print(usage)


def create_hasher(alg_class, salt, settings):
    """
    Create an object of the algorithm's class, warning if a salt was
    supplied but the algorithm doesn't support it.
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
short_to_long = {}
opt_string = ""
alg_names = []
for a in hashpw.algorithms:
    if getattr(a, 'option', None):
        if a.option in short_to_long:
            raise errors.LogicException("Short option letter '%s' for %s already used by %s" % (a.option, a.name, short_to_long[a.option]))
        short_to_long[a.option] = a.name
        # build the option sequences
        opt_string += a.option
    alg_names.append(a.name)
long_mode_map = { a: a for a in alg_names }
## long_mode_map['alias'] = 'alg'


def main():
    # == Command-line parsing ==
    # -- defaults --
    # See globals above
    global settings
    global mode
    global alg_class
    debug = False
    special = None

    # -- option handling --
    try:
        (opts, args) = getopt.getopt(sys.argv[1:], opt_string + "lvqhr:R:Ieu:V",
                                     ['help', 'rounds:', 'rounds-log:', 'username:', 'debug', 'version', 'info'] + list(long_mode_map.keys()))
    except getopt.GetoptError as e:
        barf(e, EXIT_CMDLINE_BAD)

    # Handle this here to allow for logging during option handling
    if ("--debug",'') in opts:
        ## print('debug mode ON')
        debug = True
        logging.basicConfig(level=logging.DEBUG)

    if ("--help",'') in opts or ("-h",'') in opts:
        help()
        sys.exit(EXIT_OK)

    for optpair in opts:
        if len(optpair[0]) == 2 and optpair[0][0] == "-":
            # short option
            if optpair[0][1] in short_to_long:
                if mode:
                    barf("Multiple mode options are not allowed", EXIT_MULTIPLE_MODES)
                mode = short_to_long[optpair[0][1]]
            elif optpair[0] == "-l":
                settings['long_salt'] = True
            elif optpair[0] == "-v":
                settings['verify'] = True
            elif optpair[0] == "-q":
                settings['quiet'] = True
            elif optpair[0] == "-r":
                settings['rounds'] = int(optpair[1])
            elif optpair[0] == "-R":
                settings['rounds'] = int(math.pow(2, int(optpair[1])))
            elif optpair[0] == "-V":
                special = 'version'
            elif optpair[0] == "-I":
                special = 'info'
        else:
            # long option
            if optpair[0][2:] in long_mode_map:
                if mode:
                    barf("Multiple mode options are not allowed", EXIT_MULTIPLE_MODES)
                mode = long_mode_map[optpair[0][2:]]
                logging.debug("mode (long arg) = %s", mode)
            elif optpair[0][2:] == 'rounds':
                settings['rounds'] = int(optpair[1])
            elif optpair[0][2:] == 'rounds-log':
                settings['rounds'] = int(math.pow(2, int(optpair[1])))
            elif optpair[0][2:] == 'version':
                special = 'version'
            elif optpair[0][2:] == 'info':
                special = 'info'

    # -- pre-preparation --
    try:
        hashpw.init(settings)
    except errors.InvalidArgException as e:
        barf(str(e), EXIT_CMDLINE_BAD)
    alg_class = None

    # -- argument handling --
    if special:
        if special == 'version':
            print(program_name, "v%s" % hashpw.__version__, "by", hashpw.__author__)
        elif special == 'info':
            pass

        sys.exit(EXIT_OK)

    # handle a salt if one was supplied
    if len(args) > 0:
        salt = args[0]
        # try to guess the algorithm
        if not mode:
            mode, alg_class = hashpw.identify_salt(salt)
    else:
        if settings['verify']:
            barf("Verify mode cannot be used if no salt is supplied", EXIT_VERIFY_NO_SALT)
        salt = None

    # == preparation ==
    if not mode:
        mode = DEFAULT_MODE

    if not alg_class:
        # determine algorithm
        for a in hashpw.algorithms:
            if a.name == mode:
                alg_class = a
                break
        else:
            barf("mode " + mode + " not found", EXIT_MISSING_MODE)

    # == sanity checking ==
    if settings['verify'] and not hashpw.recognise_algorithm_by_hash(alg_class, salt):
        barf("Verify mode requires a full hash to check against", EXIT_VERIFY_PARTIAL_HASH)

    # == processing ==
    try:
        # Object not function; don't call
        hasher = create_hasher(alg_class, salt, settings)
    except errors.ShortSaltException as e:
        barf(e, EXIT_SHORT_SALT)
    except errors.SaltPrefixException as e:
        barf(e, EXIT_SALT_PREFIX)
    except errors.InvalidArgException as e:
        barf(e, EXIT_BAD_OPTION)
    except errors.RoundException as e:
        if debug:
            logging.exception(e)
        barf(e, EXIT_ROUNDS)
    except ImportError as e:
        barf("Cannot find required algorithm handler: %s" % (e,), EXIT_MISSING_HANDLER)

    # TODO: Check for stdin not a tty and read that instead
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
        if not settings['verify']:
            print(make_hash(hasher, pw1))   ## .decode('ascii'))
        else:
            # verify mode (would have barfed by now if there was no salt)
            if make_hash(hasher, pw1) == salt:
                if not settings['quiet']: print("Verify suceeded.")
            else:
                if not settings['quiet']: print("Verify failed!")
                sys.exit(EXIT_VERIFY_FAILED)       # don't re-use mismatch code
    except errors.BadAlgException as e:
        barf(e, EXIT_BAD_ALG)
