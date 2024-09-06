from ..structure import SaltedAlgorithm


class SHA512(SaltedAlgorithm):
    name = "sha-512"
    option = "5"
    prefix = "$6$"
    extra_prefix = "{SHA512-CRYPT}"
    suffix = "$"
    min_length = 98


    # This can't be a @classmethod because parent classes have to work with its properties
    @staticmethod
    def init(c, *, long_salt):
        if long_salt:
            c.salt_length = 16
        else:
            c.salt_length = 8
        SaltedAlgorithm.init(c)
