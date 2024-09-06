from ..structure import SaltedAlgorithm


class MD5(SaltedAlgorithm):
    name = "md5"
    option = "x"
    prefix = "$1$"
    suffix = ""
    min_length = 34
    salt_length = 8
