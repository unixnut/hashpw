from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

import logging

import passlib.hash

from .Argon2 import Argon2i


class DjangoArgon2(Argon2i):
    """
    Django 1.10’s Argon2 wrapper
    This is identical to argon2 itself, but with the Django-specific prefix
    "argon2" prepended.
    """

    name = "django-argon2"
    option = None
    prefix = "argon2$argon2i$"
    suffix = "$"
    min_length = 64
    salt_length = 22    # doesn't include prefix or params; not including "==" needed to decode base64
    encoded_digest_length = 43
    rounds_strategy = 'logarithmic'
    default_rounds = 3   # 4 was too high (nearly a second on a Intel Core i5-4300U CPU @ 1.90GHz)
    vanilla_default_rounds = 4


    # This can't be a @classmethod because parent classes have to work with its properties
    @staticmethod
    def init(c, **kwargs: Dict):
        super().init(c, passlib_alg=passlib.hash.django_argon2, **kwargs)


    def __init__(self, salt, *, ident=None):
        super().__init__(salt, ident=ident)

        # Parent sets self.hasher
