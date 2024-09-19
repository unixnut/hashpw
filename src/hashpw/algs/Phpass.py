from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

import logging

import passlib.hash
import passlib.utils.binary

from ..structure import PLSaltedAlgorithm
from .. import errors


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
    digest_length = 22
    rounds_strategy = 'logarithmic'


    # This can't be a @classmethod because parent classes have to work with its properties
    @staticmethod
    def init(c, **kwargs: Dict):
        c.set_rounds(17, kwargs)
        super().init(c, **kwargs)


    ## @classmethod
    ## def final_prep(c):
    ##     """[Override]"""
    ##     c.rounds=17
    ##     ## c.round_id_chars = "23456789ABCDEFGHIJKLMNOP"
    ##     ## c.round_id_chars = "789ABCDEFGHIJKLMNOPQRSTU"

    ##     # Pass it up the hierarchy
    ##     PLSaltedAlgorithm.final_prep()


    def __init__(self, salt):
        super().__init__(salt)

        # These include the rounds char
        startidx = len(self.prefix) + 1
        endidx   = len(self.prefix) + self.salt_length
        if salt:
            # This salt might not match the values set by init()
            rounds = passlib.utils.binary.h64.decode_int6(salt[3].encode('ascii'))
            logging.debug("Parsing salt: len(s)=%d, startidx=%d, endidx=%d, rounds=%d",
                          len(salt), startidx, endidx, rounds)
        else:
            rounds = self.rounds
            salt   = self.salt

        try:
            self.hasher = passlib.hash.phpass.using(salt=salt[startidx:endidx], rounds=rounds)
        except ValueError as e:
            raise errors.RoundException("Rounds cannot be more than 30") from e


    @classmethod
    def generate_salt(c):
        """Calculates an encoded salt string, including prefix, for this algorithm."""
        salt_chars = PLSaltedAlgorithm.generate_raw_salt()[0:8]
        round_char = passlib.utils.binary.h64.encode_int6(c.rounds).decode("ascii")
        s = c.prefix + round_char + salt_chars
        return s
