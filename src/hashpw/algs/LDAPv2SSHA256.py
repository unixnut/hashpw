from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

import hashlib
import logging

from ..structure import BinarySaltedAlgorithm
from .. import errors


class LDAPv2SSHA256(BinarySaltedAlgorithm):
    """
    LDAPv2 salted SHA256 digest
    See https://passlib.readthedocs.io/en/stable/lib/passlib.apps.html#passlib.apps.ldap_context
    """

    name = "ldapv2-ssha256"
    option = None
    prefix = "{SSHA256}"
    suffix = ""
    min_length = 65
    salt_length = 8
    digest_length = 32


    def hash(self, plaintext: str):
        import binascii
        salt_h = binascii.hexlify(self.salt)
        val = self.generic_hash(hashlib.sha256, plaintext)
        extracted_salt_h = binascii.hexlify(self.extract_salt(val))
        logging.debug("salt1 = %s, salt2 = %s", salt_h, extracted_salt_h)
        return val
