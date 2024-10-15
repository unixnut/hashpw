from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

import base64
import logging

import passlib.hash

from ..extra_structure import PLSaltedAlgorithm
from .. import utils


# TODO: Inherit from PHCSaltedAlgorithm instead
class SCrypt(PLSaltedAlgorithm):
    """From IETF's RFC 7914: The scrypt Password-Based Key Derivation Function

    Originally developed as part of the Tarsnap online backup system
    SCrypt KDF homepage: https://www.tarsnap.com/scrypt.html

    https://en.wikipedia.org/wiki/Scrypt
    """

    # Example: $scrypt$ln=16,r=8,p=1$J2KpyY1hfrH87lrx+HYEtw$1iWDjp6ya2IEfvOkG+YCh4hU62MV8Ow/RoauZLNxVGI

    name = "scrypt"
    option = None
    prefix = "$scrypt$"
    suffix = "$"
    min_length = 87
    salt_length = 22    # doesn't include prefix or params; not including "==" needed to decode base64
    encoded_digest_length = 43
    rounds_strategy = 'logarithmic'
    default_rounds = 12   # 13 was too high (nearly a second on a Intel Core i5-4300U CPU @ 1.90GHz)
    vanilla_default_rounds = 16
    block_size = 8
    parallelism = 1


    # This can't be a @classmethod because parent classes have to work with its properties
    @staticmethod
    def init(c, **kwargs: Dict):
        c.set_rounds(extra_args=kwargs)

        # Count the fixed chars plus the fragments (just need a minimum)
        n = len("ln=8,r=8,p=1$")  # FIXME
        ## n = len(",".join(f'{k}={v}' for k, v in fragments['params'])) + 1
        c.salt_prefix_len = len(c.prefix) + n
        super().init(c, comp_extra=n, **kwargs)


    @classmethod
    def verify(c, password: str, salt: str) -> bool:
        return passlib.hash.scrypt.verify(password, salt)


    ## classmethod
    ## def generate_salt(c):
    ##    """
    ##    Calculates an encoded salt string, including prefix, for this algorithm.
    ##    This doesn't include base64 padding characters (2 "=").

    ##    [Override]
    ##    """

    ##    salt_chars = super().generate_raw_salt(raw_byte_count=16, base64_default=True)
    ##    logging.debug("Generated salt, len(s)=%d: %s", len(salt_chars), salt_chars)
    ##    # Note: 'ln' param means logarithmic round count and 'r' param means block size; see
    ##    # https://passlib.readthedocs.io/en/stable/lib/passlib.hash.scrypt.html
    ##    # (although the author thought 'ln' meant linear rounds)
    ##    # TODO: See init() and use PHCSaltedAlgorithm::phc_param_string() when written
    ##    s = "%sln=%d,r=%d,p=%d$%s" % (c.prefix, c.rounds, c.block_size, c.parallelism,
    ##                                  salt_chars[:c.salt_length])
    ##    return s


    def prep(self) -> Dict:
        info = { 'rounds': self.rounds }

        return info


    def __init__(self, salt):
        super().__init__(salt)

        # This should work, but needs something like
        # PHCSaltedAlgorithm::parse_phc_fragments() (See Argon2.py)
        ## if salt:
        ##     # This salt might not match the values set by init()
        ##     tokens = salt.split("$")
        ##     salt_length = len(tokens[3])
        ##     startidx = len(self.prefix) + 1 + len(tokens[2]) + 1
        ##     endidx   = startidx + salt_length + len(self.suffix)
        ##     ...   = PHCSaltedAlgorithm::parse_phc_fragments(salt)
        ##     # TODO: This needs extra logic to extract block_size and parallelism
        ##     info = self.prep(...)
        ##     ## logging.debug("Parsing salt: len(s)=%d, comp_len=%d, salt_length=%d, rounds=%d",
        ##     ##               len(salt), endidx, salt_length, info['rounds'])
        ## else:
        ##     startidx = len(self.prefix) + 2 + len(self.salt.split("$")[2])   ## self.salt_prefix_len
        ##     endidx   = startidx + self.salt_length + len(self.suffix)
        ##     rounds   = self.rounds
        ##     salt     = self.salt
        ##     info = self.prep()   # Use class variables (defaults or set by options)
        ##     ## logging.debug("Full salt string: len(s)=%d, comp_len=%d, salt_length=%d, rounds=%d",
        ##     ##               len(salt), endidx, self.salt_length, info['rounds'])

        if salt:
            raise NotImplementedError("Hashing with pre-existing salt not supported")
        else:
            info = self.prep()
        logging.debug("Hashing with %d rounds", info['rounds'])
        ## logging.debug("Hashing with salt '%s' (startidx=%d, endidx=%d) and %d rounds",
        ##               info['salt'], startidx, endidx, rounds)
        self.hasher = passlib.hash.scrypt.using(**info)
