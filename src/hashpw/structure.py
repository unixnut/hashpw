from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

import crypt
import logging
import math
import random
import struct

from . import errors
from . import utils


class Algorithm(object):
    supports_salt = False
    rounds_strategy = None


    # This can't be a @classmethod because it has to work with subclass properties
    @staticmethod
    def init(c, **kwargs):
        """
        Called by the top level, regardless of whether the class is instantiated.
        """

        # Catch-call in case set_rounds() wasn't called
        if kwargs.get('rounds', False):
            c.rounds = -1


    # DEPRECATED
    @classmethod
    def final_prep(c):
        """Called by the constructor, i.e. only if the algorithm class is
        actually going to be used.  Initialises things in the class that are
        used by various class helper methods.

        Designed to be overridden.  Subclasses should call this method on their
        superclass, but beware that if that superclass inherits final_prep(), its
        class object is still where attributes will be set."""
        ## print "Algorithm.final_prep()..."
        pass


    @classmethod
    def set_rounds(c, default_rounds: int = None, *, extra_args: Dict):
        """
        Figure out how many hash algorithm rounds to use based on command-line
        option (if any) or the class's default.

        If present, the 'rounds' element in @p extra_args is removed after
        processing.  Therefore this method must be called *before* the
        calling method's class's parent class's init() method.
        """

        try:
            rounds = extra_args.pop('rounds')
        except KeyError:
            rounds = False

        # rounds can have one of three kinds of value:
        #   integer > 0 passed on command-line
        #   integer == 0 passed on command-line
        #   False default from settings, which is a defaultdict(bool); CAREFUL: will compare equal with 0
        if rounds:
            if c.rounds_strategy == 'logarithmic':
                c.rounds = math.ceil(math.log2(rounds))
            elif c.rounds_strategy == 'numeric':
                c.rounds = rounds
            else:
                # Invalid value that will trip the constructor check
                c.rounds = -1
        elif rounds is not False and rounds == 0:
            # Special case that uses the passlib default
            c.rounds = c.vanilla_default_rounds
            logging.debug("Using passlib rounds=%d", c.vanilla_default_rounds)
        else:
            if default_rounds is not None:
                c.rounds = default_rounds
            else:
                # This will match the rounds_strategy so doesn't need to be converted
                c.rounds = c.default_rounds


    def __init__(self):
        if not self.rounds_strategy and hasattr(self, 'rounds'):
            raise errors.InvalidArgException("Algorithm %s doesn't support changing the round count" % self.name)
        # DEPRECATED
        self.final_prep()


    @classmethod
    def recognise_full(c, s):
        """Returns whether or not @p s matches the encoding format of algorithm @p c"""
        return len(s) >= c.min_length and s[:len(c.prefix)] == c.prefix


    def hash(self, plaintext):
        """Returns an encoded hash"""



# TODO: RoundsMixin with init() that calls c.set_rounds()
# (this will implicitly use __mro__ to call multiple parent init())



class SaltedAlgorithm(Algorithm):
    """Stores a salt, which includes the prefix."""

    supports_salt = True
    supports_long_salt = False
    r = random.SystemRandom()


    # This can't be a @classmethod because it has to work with subclass properties
    @staticmethod
    def init(c, **kwargs):
        super().init(c, **kwargs)
        c.comp_len = len(c.prefix) + c.salt_length + len(c.suffix)


    def __init__(self, salt):
        # Note that unlike SaltedAlgorithm, Algorithm's constructor doesn't take
        # an argument
        super().__init__()

        if salt:
            self.salt = self.extract_salt(salt)
        else:
            self.salt = self.generate_salt()


    @classmethod
    def recognise_full(c, s):
        """Returns whether or not @p s matches this algorithm's encoding format"""
        return len(s) >= c.min_length and c.recognise_salt_internal(s)


    @classmethod
    def recognise_salt_internal(c, s):
        """Returns whether or not @p s matches the leading part of this
        algorithm's encoding format"""
        return s[:len(c.prefix)] == c.prefix


    @classmethod
    def recognise_salt(c, s):
        """Returns whether or not @p s matches the leading part of this
        algorithm's encoding format and is long enough to contain a salt."""
        return c.recognise_salt_internal(s) and len(s) >= c.comp_len


    @classmethod
    def generate_salt(c, raw_byte_count=12, *, padding_byte=None):
        """Calculate an encoded salt string, including prefix, for algorithm @p c ."""

        salt = c.prefix + c.generate_raw_salt(raw_byte_count, padding_byte=padding_byte)[:c.salt_length] + c.suffix

        return salt


    @classmethod
    def generate_raw_salt(c, raw_byte_count=12, *, padding_byte=None):
        """Calculate a base64-encoded salt string.  @p raw_byte_count can be up to 16."""

        # make a salt consisting of 96 bits of random data, packed into a
        # string, encoded using a variant of base-64 encoding
        if padding_byte is not None:
            rand_bits = struct.pack('<QQ', c.r.getrandbits(64), c.r.getrandbits(64))[:raw_byte_count] + padding_byte
        else:
            rand_bits = struct.pack('<QQ', c.r.getrandbits(64), c.r.getrandbits(64))[:raw_byte_count]
        salt = utils.base64encode(rand_bits)

        return salt


    @classmethod
    def extract_salt(c, s):
        """Takes the prefix-plus-salt from the argument."""
        logging.debug("string = %s", s)
        c.check_salt(s)

        if c.supports_long_salt:
            logging.debug("Extracting salt: len(s)=%d, c.comp_len=%d, c.salt_length=%d",
                           len(s), c.comp_len, c.salt_length)
            # Ensure it isn't a short salt indicated by presence of delimiter sooner
            if len(s) > c.comp_len and s[c.comp_len-1] != c.suffix:
                # long salt in hash
                return s[:c.comp_len+c.salt_length]

        return s[:c.comp_len]


    @classmethod
    def check_salt(c, salt):
        """
        Checks that the supplied salt conforms to the required format of the
        current mode.
        """

        # TO-DO: warn if the supplied salt is too long (don't warn on whole password)
        if len(salt) < c.comp_len:
            raise errors.ShortSaltException()
        elif not c.recognise_salt_internal(salt):
            raise errors.SaltPrefixException("supplied salt should start with " + c.prefix)


    def hash(self, plaintext):
        """Returns an encoded hash"""

        return_value = crypt.crypt(plaintext, self.salt)

        # Check that the hash starts with the salt; otherwise, crypt(3) might
        # not understand the algorithm implied by the salt format
        if self.extract_salt(return_value) != self.salt:
            raise errors.BadAlgException(self.name + " hashing does not appear to be supported on this platform")

        return return_value



class BinarySaltedAlgorithm(SaltedAlgorithm):
    """
    For algorithms that use binary salts.

    These all use hash = prefix + base64encode(alg(digest + salt))
    """

    # This can't be a @classmethod because it has to work with subclass properties
    @staticmethod
    def init(c, **kwargs):
        """Ensure that check_salt() checks the length of the whole hash."""
        c.comp_len = c.min_length


    @classmethod
    def generate_salt(c):
        """Calculates a binary salt string for algorithm @p c ."""

        if c.salt_length > 8:
            rand_bits = struct.pack('<QQ', c.r.getrandbits(64), c.r.getrandbits(64))
        else:
            rand_bits = struct.pack('<Q', c.r.getrandbits(64))
        salt = rand_bits[:c.salt_length]

        return salt


    @classmethod
    def extract_salt(c, hash):
        """Takes the prefix-plus-salt from the argument and if valid, decodes it."""
        c.check_salt(hash)

        # decode everything after the prefix
        bits = utils.base64decode(hash[len(c.prefix):])

        # return everything after the digest part of the decoded bits
        return bits[c.digest_length:]


    def generic_hash(self, alg_fn: Type, plaintext: str):
        """Returns an encoded hash using a given basic hashing algorithm"""

        input_byte_str = plaintext.encode("UTF-8")
        context = alg_fn(input_byte_str)
        context.update(self.salt)
        output_byte_str = context.digest()
        return self.prefix + utils.base64encode(output_byte_str + self.salt)



class PLSaltedAlgorithm(SaltedAlgorithm):
    """
    Specific class for algorithms that use passlib.

    Class is required to set `self.hasher` in `__init__()`.
    """

    def hash(self, plaintext):
        """
        Make a hash using 'passlib' (unlike parent that uses 'crypt').

        Doesn't use PasswordHash.hash_password() because that generates its
        own salt.  Instead, use the internal function that is used when
        PasswordHash.portable_hashes is true.
        """

        return self.hasher.hash(plaintext)
