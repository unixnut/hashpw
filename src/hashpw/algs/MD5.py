from ..structure import SaltedAlgorithm


class MD5(SaltedAlgorithm):
    name = "md5"
    option = "m"
    prefix = "$1$"
    suffix = ""
    min_length = 34
    salt_length = 8
