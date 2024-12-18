from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

import logging
import math

import passlib.hash
import passlib.utils

from ..extra_structure import PLSaltedAlgorithm


class PBKDF2(PLSaltedAlgorithm):
    """PBKDF2 with Django prefix"""

    name = "django-pbkdf2"
    aliases = ("django-pbkdf2-sha256",)
    option = "d"
    prefix = "pbkdf2_sha256"
    suffix = "$"
    min_length = 70     # prefix + '$' + rounds(at least 2 chars) + '$' + salt + '$' + 44 chars
    supports_long_salt = True
    rounds_strategy = 'numeric'
    default_rounds = 500000
    vanilla_default_rounds = 29000

    # Example: pbkdf2_sha256$250000$sENX0bGHYNvD$KZ7cHVogLq80TiiYrYx6C19gIFikf9ekV08mFaG2+lE=

    # This can't be a @classmethod because parent classes have to work with its properties
    @staticmethod
    def init(c, *, long_salt: bool = False, **kwargs: Dict):
        """Ensure that check_salt() checks the length of the whole hash."""

        if long_salt:
            c.salt_length = 16
        else:
            c.salt_length = 12

        c.set_rounds(extra_args=kwargs)

        # Count the fixed chars plus the number of digits
        n = 1 + math.ceil(math.log10(c.rounds)) + 1  # E.g. 8 for pbkdf2_sha256$260000$
        c.salt_prefix_len = len(c.prefix) + n
        PLSaltedAlgorithm.init(c, comp_extra=n, **kwargs)


    @classmethod
    def generate_salt(c):
        """
        Calculates an encoded salt string, including prefix, for this algorithm.

        [Override]
        """

        salt_chars = passlib.utils.getrandstr(passlib.utils.rng,
                                              passlib.hash.django_pbkdf2_sha256.salt_chars,
                                              c.salt_length)
        s = "%s$%d$%s$" % (c.prefix, c.rounds, salt_chars)
        return s


    def __init__(self, salt):
        super().__init__(salt)

        if salt:
            # This salt might not match the values set by init()
            tokens = salt.split("$")
            salt_length = len(tokens[2])
            startidx = len(self.prefix) + 1 + len(tokens[1]) + 1
            endidx   = startidx + salt_length
            rounds   = int(tokens[1])
            logging.debug("Parsing salt: len(s)=%d, comp_len=%d, salt_length=%d, rounds=%d",
                          len(salt), startidx + salt_length + len(self.suffix),
                          salt_length, rounds)
        else:
            ## print(self.salt[self.salt_prefix_len:])
            startidx = self.salt_prefix_len
            endidx   = self.salt_prefix_len + self.salt_length
            rounds   = self.rounds
            salt     = self.salt

        info = { 'salt':   salt[startidx:endidx], ## salt[startidx:-1],
                 'rounds': rounds }
        logging.debug("Hashing with salt '%s' (startidx=%d, endidx=%d) and %d rounds",
                      info['salt'], startidx, endidx, rounds)
        self.hasher = passlib.hash.django_pbkdf2_sha256.using(**info)
