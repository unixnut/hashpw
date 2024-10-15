from ..structure import SaltedAlgorithm


class MD5(SaltedAlgorithm):
    """Unix MD5 crypt"""

    # Example: $1$sxLRikdD$fLSD/TXNa643xEny24rjA/

    name = "md5"
    option = "m"
    prefix = "$1$"
    extra_prefix = "MD5-CRYPT"
    suffix = ""
    min_length = 34
    salt_length = 8    # doesn't include prefix
