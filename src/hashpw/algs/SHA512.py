from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

from ..structure import SaltedAlgorithm


class SHA512(SaltedAlgorithm):
    """
    Unix SHA512 crypt
    Linux standard password hashing method
    """

    name = "sha-512"
    option = "5"
    prefix = "$6$"
    extra_prefix = "{SHA512-CRYPT}"
    suffix = "$"
    min_length = 98
    encoded_digest_length = 86
    supports_long_salt = True


    # This can't be a @classmethod because parent classes have to work with its properties
    @staticmethod
    def init(c, *, long_salt: bool = False, **kwargs: Dict):
        if long_salt:
            c.salt_length = 16
        else:
            c.salt_length = 8
        SaltedAlgorithm.init(c, **kwargs)
