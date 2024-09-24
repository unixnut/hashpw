from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

from ..structure import SaltedAlgorithm


class Blowfish(SaltedAlgorithm):
    """blowfish A.K.A. BCrypt (older "$2a$" prefix)"""

    name = "blowfish-old"
    option = "O"
    prefix = "$2a$"
    suffix = ""
    min_length = 60
    salt_length = 29
    encoded_digest_length = 31
    rounds_strategy = 'logarithmic'
    default_rounds = 12   # 13 was too high (nearly a second on a Intel Core i5-4300U CPU @ 1.90GHz)
    vanilla_default_rounds = 12


    # This can't be a @classmethod because parent classes have to work with its properties
    @staticmethod
    def init(c, **kwargs: Dict):
        c.set_rounds(extra_args=kwargs)
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
        hash_bytes = bcrypt.hashpw(plaintext.encode('ascii'),
                                   self.salt.encode('ascii'))
        return hash_bytes.decode('ascii')


    @classmethod
    def generate_salt(c):
        """Calculates an encoded salt string, including prefix, for this algorithm."""

        # py-bcrypt used to use log_rounds parameter
        salt = bcrypt.gensalt(rounds=c.rounds).decode('ascii')
        tweaked_salt = salt[0:2] + 'a' + salt[3:]
        return tweaked_salt
