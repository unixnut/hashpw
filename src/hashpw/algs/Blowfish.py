from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

from ..structure import SaltedAlgorithm


class Blowfish(SaltedAlgorithm):
    """See https://pypi.org/project/py-bcrypt/"""
    name = "blowfish"
    option = "b"
    prefix = "$2a$"
    extra_prefix = "{BLF-CRYPT}"
    suffix = ""
    min_length = 60
    salt_length = 29
    rounds_strategy = 'logarithmic'


    # This can't be a @classmethod because parent classes have to work with its properties
    @staticmethod
    def init(c, **kwargs: Dict):
        c.set_rounds(13, kwargs)
        super().init(c, **kwargs)


    @classmethod
    def final_prep(c):
        # Pass it up the hierarchy
        SaltedAlgorithm.final_prep()

        global bcrypt
        import bcrypt


    ## def __init__(self, salt):
    ##     super().__init__(salt)


    def hash(self, plaintext):
        return bcrypt.hashpw(plaintext, self.salt)


    @classmethod
    def generate_salt(c):
        """Calculates an encoded salt string, including prefix, for this algorithm."""
        return bcrypt.gensalt(log_rounds=c.rounds)
