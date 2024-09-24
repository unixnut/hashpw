from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

from ..structure import SaltedAlgorithm


class SHA256(SaltedAlgorithm):
    """Unix SHA256 crypt"""

    name = "sha-256"
    option = "2"
    prefix = "$5$"
    extra_prefix = "{SHA256-CRYPT}"
    suffix = "$"
    min_length = 55
    encoded_digest_length = 43
    supports_long_salt = True


    # This can't be a @classmethod because parent classes have to work with its properties
    @staticmethod
    def init(c, *, long_salt: bool = False, **kwargs: Dict):
        if long_salt:
            c.salt_length = 16
        else:
            c.salt_length = 8
        SaltedAlgorithm.init(c, **kwargs)
