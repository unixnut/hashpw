"""Top-level package for Universal password hash generator and verifier"""

__author__ = """Alastair Irvine"""
__email__ = 'alastair@plug.org.au'
__version__ = '2.6.0'


from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

import logging

from .algs.ApacheMD5 import ApacheMD5
from .algs.ApacheSHA1 import ApacheSHA1
from .algs.BasicMD5 import BasicMD5
from .algs.Blowfish import Blowfish
from .algs.BCrypt import BCrypt, BCryptVariant
from .algs.Crypt import Crypt
from .algs.ExtDes import ExtDes
from .algs.LDAPv2SMD5 import LDAPv2SMD5
from .algs.LDAPv2SSHA256 import LDAPv2SSHA256
from .algs.LDAPv2SSHA512 import LDAPv2SSHA512
from .algs.MD5 import MD5
from .algs.MySqlSHA1 import MySqlSHA1
from .algs.OldPassword import OldPassword
from .algs.PBKDF2 import PBKDF2
from .algs.PhpBB3 import PhpBB3
from .algs.Phpass import Phpass
from .algs.SHA256 import SHA256
from .algs.SHA512 import SHA512
from .algs.SSHA import SSHA


# *** DEFINITIONS ***
# Algorithms with longer prefixes need to appear earlier in this list
algorithms = (PBKDF2, ApacheMD5, ApacheSHA1, LDAPv2SSHA256, LDAPv2SSHA512, LDAPv2SMD5, SSHA, BCrypt, BCryptVariant, Blowfish, MD5, SHA256, SHA512, MySqlSHA1, Phpass, PhpBB3, BasicMD5, ExtDes, Crypt, OldPassword)


# *** FUNCTIONS ***
# Set by init()
recognise_algorithm = None


def recognise_algorithm_by_hash(algorithm, s):
    return algorithm.recognise_full(s)


def recognise_algorithm_by_salt(algorithm, s):
    if algorithm.supports_salt:
        return algorithm.recognise_salt(s)
    else:
        return algorithm.recognise_full(s)
        ## return False


def identify_salt(salt: str) -> Optional[Tuple[str, Type]]:
    for a in algorithms:
        if recognise_algorithm(a, salt):
            # mode, alg_class
            return a.name, a


def init(settings: Dict):
    global recognise_algorithm

    if settings['verify']:
        recognise_algorithm = recognise_algorithm_by_hash
    else:
        recognise_algorithm = recognise_algorithm_by_salt

    # have to do this after option handling but before algorithm recognition
    for a in algorithms:
        logging.debug("Initialising algorithm %s", a.name)
        a.init(a, long_salt=settings['long_salt'], rounds=settings['rounds'])


# *** MAINLINE ***
