from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

import logging

import passlib.hash

from ..extra_structure import PLSaltedAlgorithm


# TODO: Inherit from PHCSaltedAlgorithm (as well?)
class Argon2Base(PLSaltedAlgorithm):
    """
    Abstract base class for actual Argon2 algorithms.

    Note: passlib.hash.argon2 encodes passwords using UTF-8 before hashing.
    """

    suffix = "$"
    salt_length = 22    # doesn't include prefix or params; not including "==" needed to decode base64
    encoded_digest_length = 43
    rounds_strategy = 'logarithmic'
    default_rounds = 5   # Last resort in case not defined by a subclass
    vanilla_default_rounds = 4


    # This can't be a @classmethod because parent classes have to work with its properties
    @staticmethod
    def init(c, *, passlib_alg: Type = passlib.hash.argon2, **kwargs: Dict):
        c.set_rounds(extra_args=kwargs)

        # Count the fixed chars plus the fragments (just need a minimum)
        n = len("m=512,t=3,p=2$")  # FIXME
        ## n = len(",".join(f'{k}={v}' for k, v in fragments['params'])) + 1
        c.salt_prefix_len = len(c.prefix) + 5 + n   # E.g. "v=19$"
        super().init(c, comp_extra=n, **kwargs)

        c.passlib_alg = passlib_alg


    @classmethod
    def verify(c, password: str, salt: str) -> bool:
        return c.passlib_alg.verify(password, salt)


    def prep(self) -> Dict:
        info = { 'rounds': self.rounds }

        return info


    def __init__(self, salt, *, ident: str):
        super().__init__(salt)

        if salt:
            raise NotImplementedError("Hashing with pre-existing salt not supported")
        else:
            info = self.prep()
        if ident:
            info['type'] = ident  # E.g. "D"
        logging.debug("Hashing with %d rounds", info['rounds'])

        self.hasher = self.passlib_alg.using(**info)



class Argon2i(Argon2Base):
    """
    Argon2 algorithm best suited to password hashing and password-based key derivation
    See https://github.com/P-H-C/phc-winner-argon2
    """

    # Example: $argon2i$v=19$m=65536,t=3,p=4$hBBiDMEYg3DO+R8DoNS6tw$fDY/gS+/voMl7pUrNzB5btS9MY76R/LcaaiuFJcst40

    name = "argon2i"
    option = "z"
    prefix = "$argon2i$"
    min_length = 58
    default_rounds = 3   # 4 was too high (nearly a second on a Intel Core i5-4300U CPU @ 1.90GHz)
    vanilla_default_rounds = 4


    def __init__(self, salt, *, ident: str = "I"):
        super().__init__(salt, ident=ident)

        # Parent sets self.hasher



class Argon2d(Argon2Base):
    """
    Argon2 algorithm more vulnerable to tradeoff attacks but highly resistant
    against GPU cracking attacks; see https://github.com/P-H-C/phc-winner-argon2
    """

    name = "argon2d"
    prefix = "$argon2d$"
    min_length = 58
    default_rounds = 3   # 4 was too high (nearly a second on a Intel Core i5-4300U CPU @ 1.90GHz)
    vanilla_default_rounds = 4


    def __init__(self, salt, *, ident: str = "D"):
        super().__init__(salt, ident=ident)

        # Parent sets self.hasher



class Argon2id(Argon2Base):
    """
    A hybrid Argon2 algorithm with some resistance to side-channel cache timing
    attacks and good resistance to GPU cracking attacks.
    See https://github.com/P-H-C/phc-winner-argon2
    """

    name = "argon2id"
    prefix = "$argon2id$"
    min_length = 59
    default_rounds = 3   # 4 was too high (nearly a second on a Intel Core i5-4300U CPU @ 1.90GHz)
    vanilla_default_rounds = 4


    def __init__(self, salt, *, ident: str = "ID"):
        super().__init__(salt, ident=ident)

        # Parent sets self.hasher
