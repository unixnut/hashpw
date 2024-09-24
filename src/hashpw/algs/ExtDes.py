from ..structure import SaltedAlgorithm


class ExtDes(SaltedAlgorithm):
    """Extended DES, with a nine character salt (FreeBSD 4.x and NetBSD only)"""

    name = "ext-des"
    option = "x"
    prefix = "_"
    suffix = ""
    min_length = 20
    salt_length = 8


    ## @classmethod
    ## def recognise_salt(c, s):
    ##     return False
