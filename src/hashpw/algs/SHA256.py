from ..structure import SaltedAlgorithm


class SHA256(SaltedAlgorithm):
    name = "sha-256"
    option = "2"
    prefix = "$5$"
    extra_prefix = "{SHA256-CRYPT}"
    suffix = "$"
    min_length = 55


    # This can't be a @classmethod because parent classes have to work with its properties
    @staticmethod
    def init(c, *, long_salt):
        if long_salt:
            c.salt_length = 16
        else:
            c.salt_length = 8
        SaltedAlgorithm.init(c)
