from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

import copy
import logging
import math
import random

from ... import errors
from ...structure import SaltedAlgorithm
from .YescryptSettings import YescryptParams
from .YescryptSettings import N2log2
from .YescryptFlags import YescryptFlags


class YesCrypt(SaltedAlgorithm):
    """
    Designed by Solar Designer

    Current Linux standard password hashing method
    """

    prefix = "$y$"
    name = "yescrypt"
    option = "Y"
    suffix = "$"
    min_length = 73
    salt_length = 22    # doesn't include prefix or params; not including "==" needed to decode base64
    encoded_digest_length = 43
    rounds_strategy = 'logarithmic'
    default_rounds = 15
    params = { 'block_size': 32, 'parallelism': 2, 'time_factor': 5 }
    vanilla_default_rounds = 12


    # This can't be a @classmethod because parent classes have to work with its properties
    @staticmethod
    def init(c, **kwargs: Dict):
        """
        Ensure that check_salt() checks the length of the whole hash.
        [Override]
        """

        c.set_rounds(extra_args=kwargs)
        if 'params' in kwargs and kwargs['params']:
            c.set_other_params(kwargs['params'])

        n = 4  # params chars (minimum) and delimiter
        # Number of characters before salt
        c.salt_prefix_len = len(c.prefix) + n

        super().init(c, comp_extra=n, **kwargs)


    @classmethod
    def generate_salt(c) -> str:
        """
        Calculates an encoded salt string, including prefix, for this algorithm.
        This doesn't include base64 padding characters (2 "=").

        [Override]
        """

        # Use bits and then encode them (instead of randomly generating encoded characters)
        rand_salt_chars = c.generate_raw_salt(raw_byte_count=16)
        # For YesCrypt, the salt is actually 132 bits (instead of 128 bits
        # normally used by algorithms with a 22 char salt, which ignore the
        # extra 4 bits).  The 6 least significant bits must be one of the
        # values 110100, 110101, 111110 or 111111.  So change the last char of
        # the encoded salt (not including base64 padding, which is elided) to
        # one of the 4 permissible characters to achieve this.
        char_list = random.sample('01./', 1)
        salt_chars = rand_salt_chars[:c.salt_length-1] + char_list[0]
        logging.debug("Generated salt, len(s)=%d: %s", len(salt_chars), salt_chars)
        # Format: see https://unix.stackexchange.com/a/724514

        ## user_params = copy.copy(c.get_default_params())
        params = { 'N': int(math.pow(2, c.rounds)), 'r': c.params['block_size'],
                   'p': c.params['parallelism'], 't': c.params['time_factor'] }
        encoded_params = str(YescryptParams(**params))
        s = "%s%s$%s%s" % (c.prefix, encoded_params, salt_chars, c.suffix)
        logging.debug("Full salt, len(s)=%d: %s", len(s), s)
        return s


    @classmethod
    def extract_salt(c, s: str) -> str:
        """
        Extract a full salt prefix from a hash.

        [Override]
        """

        salt, params = c.get_salt_info(s)
        return salt


    @classmethod
    def get_salt_info(c, s: str) -> Tuple[str, Dict]:
        """
        Extract a full salt string and a mapping of information about it (called the
        parameters) from a hash.
        
        [Override]
        """

        if c.recognise_salt_internal(s):
            tokens = s.split("$")
            if len(tokens) == 4:
                raise ValueError("Hash invalid: in crypt format")
            else:
                logging.debug("%d tokens found", len(tokens))
                if len(tokens) == 5:
                    ## salt = c.build_full_salt(rounds=, salt_chars)
                    salt = s[:len(c.prefix) + len(tokens[2]) + 1 + c.salt_length + len(c.suffix)]
                    params = c.parse_params(tokens[2])

                    return salt, params
                else:
                    raise ValueError("Hash format invalid")
        else:
            raise ValueError("Hash does not start with " + c.prefix)


    @classmethod
    def parse_params(c, s: str) -> Dict:
        """YesCrypt params parsing"""

        params = YescryptParams.decode(s)
        return { 'rounds': c.rounds_to_logarithmic(params.N),
                 'block_size': params.r,
                 'parallelism': params.p,
                 'time_factor': params.t }


    @classmethod
    def get_default_params(c) -> Dict:
        return {}


    @classmethod
    def set_other_params(c, p: Dict) -> Dict:
        local_p = copy.copy(p)
        for param in ('block_size', 'parallelism', 'time_factor'):
            try:
                val = local_p.pop(param)
                c.params[param] = int(val)
            except KeyError:
                pass
        # Check if any elements weren't popped
        if local_p:
            raise errors.InvalidArgException("Unknown parameter name '%s'" % next(iter(p.keys())))


    ## @classmethod
    ## def check_salt(c, salt: str):
    ##     logging.debug("salt: %s, comp_len=%d", salt, c.comp_len)
    ##     super().check_salt(salt)
