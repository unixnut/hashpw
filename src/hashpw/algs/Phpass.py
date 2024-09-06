import passlib.hash
import passlib.utils.binary

from ..structure import PLSaltedAlgorithm


class Phpass(PLSaltedAlgorithm):
    """https://github.com/exavolt/python-phpass
    e.g. portable (safe MD5): $P$Bnvt73R2AZ9NwrY8agFUwI1YUYQEW5/
         Blowfish: $2a$08$iys2/e7hwWyX2YbWtjCyY.tmGy2Y.mGlV9KwIAi9AUPgBuc9rdJVe"""

    name = "phpass"
    option = "P"
    prefix = "$P$"
    suffix = ""
    min_length = 34
    salt_length = 9  # includes the round count


    @classmethod
    def final_prep(c):
        """[Override]"""
        c.rounds=17
        ## c.round_id_chars = "23456789ABCDEFGHIJKLMNOP"
        ## c.round_id_chars = "789ABCDEFGHIJKLMNOPQRSTU"

        # Pass it up the hierarchy
        PLSaltedAlgorithm.final_prep()


    def __init__(self, salt):
        super().__init__(salt)

        self.hasher = passlib.hash.phpass.using(salt=self.salt[4:], rounds=self.rounds)


    @classmethod
    def generate_salt(c):
        """Calculates an encoded salt string, including prefix, for this algorithm."""
        salt_chars = PLSaltedAlgorithm.generate_raw_salt()[0:8]
        round_char = passlib.utils.binary.h64.encode_int6(c.rounds).decode("ascii")
        s = c.prefix + round_char + salt_chars
        return s
