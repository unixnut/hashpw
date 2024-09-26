from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

import logging

import passlib.hash

from ..structure import PLSaltedAlgorithm


class BCrypt(PLSaltedAlgorithm):
    """blowfish A.K.A. BCrypt (standard prefix)"""

    name = "bcrypt"
    option = "b"
    prefix = "$2b$"
    suffix = ""
    min_length = 60
    salt_prefix_len = len(prefix) + 3  # round chars and delimiter
    salt_length = 22
    encoded_digest_length = 31
    rounds_strategy = 'logarithmic'
    default_rounds = 12   # 13 was too high (nearly a second on a Intel Core i5-4300U CPU @ 1.90GHz)
    vanilla_default_rounds = 12


    # This can't be a @classmethod because parent classes have to work with its properties
    @staticmethod
    def init(c, **kwargs: Dict):
        c.set_rounds(extra_args=kwargs)
        # 2 round count chars and a $ delimiter
        super().init(c, comp_extra=3, **kwargs)


    @classmethod
    def generate_salt(c):
        """
        Calculates an encoded salt string, including prefix, for this algorithm.

        [Override]
        """

        # Use bits and then encode them (instead of randomly generating encoded characters)
        # plus add bits before encoding so that 22 chars (which encodes more
        # than 128 bits actually used) always has a predictable value in the last char.
        # See "Padding Bits" in https://passlib.readthedocs.io/en/stable/lib/passlib.hash.bcrypt.html#deviations
        salt_chars = super().generate_raw_salt(raw_byte_count=16, padding_byte=b'\xE0')
        ## salt_chars = passlib.utils.getrandstr(passlib.utils.rng,
        ##                                       passlib.hash.bcrypt.salt_chars,
        ##                                       c.salt_length)
        s = "%s%d$%s" % (c.prefix, c.rounds, salt_chars)
        return s


    def bcrypt_prep(self, salt: str, token_offset: int = 0) -> Tuple[Dict, int, int]:
        startidx = self.salt_prefix_len
        endidx   = self.comp_len
        if salt:
            # This salt might not match the values set by init()
            tokens = salt.split("$")
            rounds   = int(tokens[2+token_offset])
            logging.debug("Parsing salt: len(s)=%d, comp_len=%d, salt_length=%d, rounds=%d",
                          len(salt), startidx + endidx + len(self.suffix),
                          self.salt_length, rounds)
        else:
            rounds   = self.rounds
            salt     = self.salt

        info = { 'salt':   salt[startidx:endidx],
                 'rounds': rounds }

        return info, startidx, endidx


    def __init__(self, salt, ident=None, *, token_offset: int = 0, passlib_alg: Type = passlib.hash.bcrypt):
        super().__init__(salt)

        info, startidx, endidx = self.bcrypt_prep(salt, token_offset)
        if ident:
            info['ident'] = ident  # E.g. "2y"
        logging.debug("Hashing with salt '%s' (startidx=%d, endidx=%d) and %d rounds",
                      info['salt'], startidx, endidx, info['rounds'])

        self.hasher = passlib_alg.using(**info)


class BCryptVariant(BCrypt):
    """blowfish A.K.A. BCrypt (variant "$2y$" prefix used by BSD)"""

    name = "bcrypt-variant"
    option = "y"
    prefix = "$2y$"
    extra_prefix = "{BLF-CRYPT}"


    def __init__(self, salt):
        super().__init__(salt, ident="2y")
