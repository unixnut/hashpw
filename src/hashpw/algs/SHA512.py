from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

import logging

from ..extra_structure import PHCSaltedAlgorithm


class SHA512(PHCSaltedAlgorithm):
    """
    Unix SHA512 crypt
    Old Linux standard password hashing method
    """

    # Examples:
    #   $6$69UJJO3e$xZZf6obOcKj/A7RC46JqqyoNeU5Ho/f0o/SgK5wkiCw4LtRgup2/pOKkXR3wi3UWkzSBP9VmJPOiFmgoHiz2s1
    #   $6$rounds=656000$3A9ckbsJmsjhE.VE$wQwDUT0trAyXc0IpLt1U4G1S.MkRruq4GX2AFU.q6AHERxYF69X3mHk34tKQy2LjrlKAlaN3qE/pMskjUnaP.0

    name = "sha-512"
    option = "5"
    prefix = "$6$"
    extra_prefix = "{SHA512-CRYPT}"
    suffix = "$"
    min_length = 98
    encoded_digest_length = 86
    supports_long_salt = True
    rounds_strategy = 'numeric'
    default_rounds = 650000
    vanilla_default_rounds = 5000


    # This can't be a @classmethod because parent classes have to work with its properties
    @staticmethod
    def init(c, *, long_salt: bool = False, **kwargs: Dict):
        if long_salt:
            c.salt_length = 16
        else:
            c.salt_length = 8

        PHCSaltedAlgorithm.init(c, **kwargs)
