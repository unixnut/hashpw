import binascii
import hashlib

from ..structure import Algorithm


class BasicMD5(Algorithm):
    """MySQL MD5()"""

    name = "basic-md5"
    option = "M"
    prefix = ""
    extra_prefix = "{PLAIN-MD5}"
    suffix = ""
    min_length = 32


    def hash(self, plaintext):
        input_byte_str = plaintext.encode("UTF-8")
        first_round_output = hashlib.md5(input_byte_str).digest()
        output_byte_str = binascii.hexlify(first_round_output)
        return output_byte_str.decode('ascii')
