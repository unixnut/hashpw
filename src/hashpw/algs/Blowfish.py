from ..structure import SaltedAlgorithm


class Blowfish(SaltedAlgorithm):
    """See https://pypi.org/project/py-bcrypt/"""
    name = "blowfish"
    option = "b"
    prefix = "$2a$"
    extra_prefix = "{BLF-CRYPT}"
    suffix = ""
    min_length = 57
    salt_length = 16


    @classmethod
    def final_prep(c):
        """[Override]"""
        c.rounds=13

        # Pass it up the hierarchy
        SaltedAlgorithm.final_prep()

        global bcrypt
        import bcrypt


    ## def __init__(self, salt):
    ##     super().__init__(salt)


    def hash(self, plaintext):
        return bcrypt.hashpw(plaintext, self.salt)


    @classmethod
    def generate_salt(c):
        """Calculates an encoded salt string, including prefix, for this algorithm."""
        return bcrypt.gensalt(log_rounds=c.rounds)
