from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

import logging

import passlib.hash

from .BCrypt import BCrypt


class DjangoBcryptSHA256(BCrypt):
    """Django 1.6’s Bcrypt+SHA256"""

    name = "django-bcrypt-sha256"
    option = None
    prefix = "bcrypt_sha256$$2b$"
    suffix = ""
    min_length = 74
    salt_prefix_len = len(prefix) + 3  # round chars and delimiter
    salt_length = 22    # doesn't include prefix or params; not including "==" needed to decode base64
    encoded_digest_length = 31
    rounds_strategy = 'logarithmic'
    default_rounds = 12   # 13 was too high (nearly a second on a Intel Core i5-4300U CPU @ 1.90GHz)
    vanilla_default_rounds = 12


    def __init__(self, salt, ident=None):
        super().__init__(salt, ident, token_offset=1, passlib_alg=passlib.hash.django_bcrypt_sha256)

        # Parent sets self.hasher


class DjangoBcryptSHA256Orig(DjangoBcryptSHA256):
    """Django 1.6’s Bcrypt+SHA256 (variant "$2a$")"""

    name = "django-bcrypt-sha256-orig"
    prefix = "bcrypt_sha256$$2a$"


    def __init__(self, salt):
        super().__init__(salt, ident="2a")

        # Parent sets self.hasher
