from typing import Set, Dict, Sequence, Tuple, List, Union, AnyStr, Iterable, Callable, Generator, Type, Optional, TextIO, IO

import logging
import math

from .structure import SaltedAlgorithm


class PHCSaltedAlgorithm(SaltedAlgorithm):
    """
    The PHC Specification states that both the version chunk and the parameter
    chunk are optional, so this covers traditional crypt format hashes too.

    @see https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
    """


    @staticmethod
    def parse_phc_fragments(s: str) -> Dict:
        """
        Split "$<id>[$v=<version>][$<param>=<value>(,<param>=<value>)*][$<salt>[$<hash>]]"
        into  { 'id': str, 'version': int, 'params': dict, 'salt': str, 'hash': str }
        """
        # Uses parse_params()

        raise NotImplementedError


    # This can't be a @classmethod because parent classes have to work with its properties
    @staticmethod
    def init(c, **kwargs: Dict):
        """Ensure that check_salt() checks the length of the whole hash."""

        c.set_rounds(extra_args=kwargs)
        # TODO: Set other param fields, e.g. from kwargs['params']: Dict

        # Count the fixed chars plus the number of digits
        if c.rounds != c.vanilla_default_rounds:
            ## n = len(PHCSaltedAlgorithm::phc_param_string(...)) + 1
            ## n = PHCSaltedAlgorithm::phc_param_len(...)  # Includes ,,,,$
            n = len("rounds=") + math.ceil(math.log10(c.rounds)) + 1   # E.g. rounds=656000$
        else:
            n = 0
        # Number of characters before salt
        c.salt_prefix_len = len(c.prefix) + n

        super().init(c, comp_extra=n, **kwargs)


    @classmethod
    def generate_salt(c, allow_basic: bool = True) -> str:
        """
        Calculates an encoded salt string, including prefix, for this algorithm.
        This doesn't include base64 padding characters (2 "=").

        [Override]
        
        @param allow_basic  Whether or not to elide the round count if same as vanilla_default_rounds
        """

        salt_byte_count = None
        if c.supports_long_salt:
            if c.salt_length == 8:
                salt_byte_count = 6
            elif c.salt_length == 12:
                salt_byte_count = 9
        logging.debug("salt_byte_count = %s", str(salt_byte_count))

        if allow_basic and c.rounds != c.vanilla_default_rounds:
            # Use bits and then encode them (instead of randomly generating encoded characters)
            if salt_byte_count:
                salt_chars = c.generate_raw_salt(salt_byte_count)
            else:
                # Use default raw_byte_count to get a long salt (16 characters)
                salt_chars = c.generate_raw_salt()
            ## salt_chars = passlib.utils.getrandstr(passlib.utils.rng,
            ##                                       passlib.hash.bcrypt.salt_chars,
            ##                                       c.salt_length)
            logging.debug("Generated salt, len(s)=%d: %s", len(salt_chars), salt_chars)
            s = c.build_full_salt(c.rounds, salt_chars)
        else:
            # Generate a basic full salt string without a round count
            if salt_byte_count:
                s = super().generate_salt(salt_byte_count)
            else:
                # Use default raw_byte_count to get a long salt (16 characters)
                s = super().generate_salt()

        return s


    @classmethod
    def build_full_salt(c, rounds: int, salt: str) -> str:
        """
        Creates a partial PHC string (no digest) consisting of the prefix,
        params, salt and suffix.
        """
        # TODO: Accept **kwargs for addtional param fields
        # TODO: Support alternative field name for rounds
        # TODO: Use PHCSaltedAlgorithm::phc_param_string()
        # TODO: Support version fragment

        return "%srounds=%d$%s%s" % (c.prefix, rounds, salt, c.suffix)


    @classmethod
    def extract_salt(c, s: str) -> str:
        """
        Extract a full salt prefix from a hash.

        Won't work when used in the degenerate case, i.e. @p s is already a
        full salt prefix, if c.suffix is empty.
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
            return c.get_salt_info_internal(s, tokens)
        else:
            raise ValueError("Hash does not start with " + c.prefix)


    @classmethod
    def parse_params(c, s: str) -> Dict:
        """
        Split out comma-separated key-value pairs into a dict.

        This is a classmethod for consistency with other classes where it has
        to be.
        """

        def kvsplit(s: str) -> Tuple[str, str]:
            """Returns a key and one value (which may include equals signs)."""
            return s.split("=", 1)

        # Build a dict from a sequence of 2-tuples
        return dict(kvsplit(param) for param in s.split(","))


    @classmethod
    def get_default_params(c) -> Dict:
        return { 'rounds': c.vanilla_default_rounds }


    @classmethod
    def get_salt_info_internal(c, s: str, tokens: Sequence[str]) -> Tuple[str, Dict]:
        """
        Extract a full salt string and a mapping of information about it (called the
        parameters) from a tokenised hash.
        """

        logging.debug("%d tokens found", len(tokens))
        if len(tokens) == 6:
            raise NotImplementedError("PHC version fragment parsing not supported")
        elif len(tokens) == 5:
            # Check for version fragment present instead of params
            if tokens[2].startswith("v="):
                raise NotImplementedError("PHC version fragment present without params fragment")

            ## salt = c.build_full_salt(rounds=, salt_chars)
            salt = s[:len(c.prefix) + len(tokens[2]) + 1 + len(tokens[3]) + len(c.suffix)]
            # Optional rounds=... field is present
            params = c.parse_params(tokens[2])

            return salt, params
        elif len(tokens) == 4:
            # Original format, e.g. $6$69UJJO3e$...
            return super().get_salt_info(s)
        else:
            raise ValueError("Hash does not conform to PHC or crypt format")



class PHCParamsSaltedAlgorithm:
    """
    Covers algorithms where the parameter chunk is not optional, unlike the
    generic format given in the PHC Specification.

    @see https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
    """

    # This can't be a @classmethod because parent classes have to work with its properties
    @staticmethod
    def init(c, **kwargs: Dict):
        """
        Ensure that check_salt() checks the length of the whole hash.
        [Override]
        """

        c.set_rounds(extra_args=kwargs)
        # TODO: Set other param fields, e.g. from kwargs['params']: Dict

        # Count the fixed chars plus the number of digits
        ## n = len(PHCSaltedAlgorithm::phc_param_string(...)) + 1
        ## n = PHCSaltedAlgorithm::phc_param_len(...)  # Includes separators: ,,,,$
        n = len("rounds=") + math.ceil(math.log10(c.rounds)) + 1   # E.g. rounds=656000$
        # Number of characters before salt
        c.salt_prefix_len = len(c.prefix) + n

        super().init(c, comp_extra=n, **kwargs)


    @classmethod
    def get_salt_info(c, s: str) -> Tuple[str, Dict]:
        if c.recognise_salt_internal(s):
            tokens = s.split("$")
            if len(tokens) == 4:
                raise ValueError("Hash invalid: in crypt format")
            else:
                ## return c.get_salt_info(s)
                return get_salt_info_internal(s, tokens)
        else:
            raise ValueError("Hash does not start with " + c.prefix)


    @classmethod
    def generate_salt(c) -> str:
        """
        Calculates an encoded salt string, including prefix, for this algorithm.
        This doesn't include base64 padding characters (2 "=").
        """

        return super().generate_salt(allow_basic=False)



class PLSaltedAlgorithm(SaltedAlgorithm):
    """
    Specific class for algorithms that use passlib.

    Class is required to set `self.hasher` in `__init__()`.
    """

    def hash(self, plaintext: str) -> str:
        """
        Make a hash using 'passlib' (unlike parent that uses 'crypt').

        Doesn't use PasswordHash.hash_password() because that generates its
        own salt.  Instead, use the internal function that is used when
        PasswordHash.portable_hashes is true.
        """

        return self.hasher.hash(plaintext)
