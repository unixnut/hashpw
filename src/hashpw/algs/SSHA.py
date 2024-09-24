import hashlib

from .. import utils
from ..structure import BinarySaltedAlgorithm


class SSHA(BinarySaltedAlgorithm):
    """LDAPv2 salted SHA1 digest"""

    name = "ssha"
    option = "S"
    prefix = "{SSHA}"
    suffix = ""
    min_length = 38
    salt_length = 4
    digest_length = 20


    def hash(self, plaintext: str):
        return self.generic_hash(hashlib.sha1, plaintext)


    def real_hash(self, plaintext: str):
        input_byte_str = plaintext.encode("UTF-8")
        context = hashlib.sha1(input_byte_str)
        context.update(self.salt)
        output_byte_str = context.digest()
        return self.prefix + utils.base64encode(output_byte_str + self.salt)
