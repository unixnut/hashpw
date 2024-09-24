import hashlib

from .. import utils
from ..structure import Algorithm


class ApacheSHA1(Algorithm):
    """Apache SHA-1 (RFC 2307; can be used by OpenLDAP)"""

    name = "apache-sha-1"
    option = "A"
    prefix = "{SHA}"
    suffix = ""
    min_length = 33


    def hash(self, plaintext):
        input_byte_str = plaintext.encode("UTF-8")
        round_output = hashlib.sha1(input_byte_str).digest()
        return self.prefix + utils.base64encode(round_output)
