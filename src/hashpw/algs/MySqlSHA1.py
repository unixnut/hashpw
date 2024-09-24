import binascii
import hashlib

from ..structure import Algorithm


class MySqlSHA1(Algorithm):
    """MySQL v4.1+ PASSWORD"""

    name = "mysql-sha-1"
    option = "p"
    prefix = "*"
    suffix = ""
    min_length = 41


    def hash(self, plaintext):
        input_byte_str = plaintext.encode("UTF-8")
        first_round_output = hashlib.sha1(input_byte_str).digest()
        second_round_output = hashlib.sha1(first_round_output).digest()
        output_byte_str = binascii.hexlify(second_round_output)
        return "*" + output_byte_str.decode('ascii').upper()
