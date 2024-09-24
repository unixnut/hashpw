from ..structure import SaltedAlgorithm


class MD5(SaltedAlgorithm):
    """Unix MD5 crypt"""

    name = "md5"
    option = "m"
    prefix = "$1$"
    extra_prefix = "MD5-CRYPT"
    suffix = ""
    min_length = 34
    salt_length = 8
