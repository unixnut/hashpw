from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

import binascii
import logging
import math

import passlib.hash
import passlib.utils

from ..extra_structure import PLSaltedAlgorithm


class GrubPBKDF2SHA512(PLSaltedAlgorithm):
    """Grub’s PBKDF2 SHA512 Hash"""

    name = "grub-pbkdf2"
    option = "g"
    prefix = "grub.pbkdf2.sha512"
    suffix = "."
    min_length = 281     # prefix + '.' + rounds(at least 2 chars) + '.' + salt + '.' + 128 chars
    salt_length = 128    # doesn't include prefix or params
    encoded_digest_length = 128
    rounds_strategy = 'numeric'
    default_rounds = 350000
    vanilla_default_rounds = 19000


    # This can't be a @classmethod because parent classes have to work with its properties
    @staticmethod
    def init(c, **kwargs: Dict):
        """Ensure that check_salt() checks the length of the whole hash."""

        c.set_rounds(extra_args=kwargs)

        # Count the fixed chars plus the number of digits
        n = 1 + math.ceil(math.log10(c.rounds)) + 1  # E.g. 8 for grub.pbkdf2.sha512.260000.
        c.salt_prefix_len = len(c.prefix) + n
        PLSaltedAlgorithm.init(c, comp_extra=n, **kwargs)


    @classmethod
    def generate_salt(c):
        """
        Calculates an encoded salt string, including prefix, for this algorithm.

        [Override]
        """

        binary_salt = passlib.utils.getrandstr(passlib.utils.rng,
                                               passlib.hash.grub_pbkdf2_sha512.salt_chars,
                                               c.salt_length // 2)
        salt_chars = binascii.hexlify(binary_salt).decode('ascii')
        s = "%s.%d.%s." % (c.prefix, c.rounds, salt_chars)
        return s


    def __init__(self, salt):
        super().__init__(salt)

        if salt:
            # This salt might not match the values set by init()
            tokens = salt.split(".")
            salt_length = len(tokens[4])
            startidx = len(self.prefix) + 1 + len(tokens[3]) + 1
            endidx   = startidx + salt_length
            rounds   = int(tokens[3])
            logging.debug("Parsing salt: len(s)=%d, comp_len=%d, salt_length=%d, rounds=%d",
                          len(salt), startidx + salt_length + len(self.suffix),
                          salt_length, rounds)
        else:
            ## print(self.salt[:self.salt_prefix_len])
            startidx = self.salt_prefix_len
            endidx   = self.comp_len - len(self.suffix)
            rounds   = self.rounds
            salt     = self.salt


        ## print(type(salt), type(salt[startidx:endidx])
        info = { 'salt':   binascii.unhexlify(salt[startidx:endidx]),
                 'rounds': rounds }
        logging.debug("Hashing with salt '%s' (startidx=%d, endidx=%d) and %d rounds",
                      info['salt'], startidx, endidx, rounds)
        self.hasher = passlib.hash.grub_pbkdf2_sha512.using(**info)
