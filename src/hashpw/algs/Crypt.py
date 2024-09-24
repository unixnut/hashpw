from ..structure import SaltedAlgorithm


class Crypt(SaltedAlgorithm):
    """crypt (DES), with a two character salt"""

    name = "crypt"
    option = "c"
    prefix = ""
    suffix = ""
    min_length = 13
    salt_length = 2


    @classmethod
    def recognise_full(c, s):
        return len(s) == c.min_length
