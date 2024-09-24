from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

import hashlib
import logging

from ..structure import BinarySaltedAlgorithm
from .. import errors


class LDAPv2SMD5(BinarySaltedAlgorithm):
    """
    LDAPv2 salted MD5 digest
    See https://passlib.readthedocs.io/en/stable/lib/passlib.apps.html#passlib.apps.ldap_context
    """

    name = "ldapv2-smd5"
    option = "L"
    prefix = "{SMD5}"
    suffix = ""
    min_length = 34
    salt_length = 4
    digest_length = 16


    def hash(self, plaintext: str):
        import binascii
        salt_h = binascii.hexlify(self.salt)
        val = self.generic_hash(hashlib.md5, plaintext)
        extracted_salt_h = binascii.hexlify(self.extract_salt(val))
        logging.debug("salt1 = %s, salt2 = %s", salt_h, extracted_salt_h)
        return val
