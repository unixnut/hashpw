from ..structure import SaltedAlgorithm


class ExtDes(SaltedAlgorithm):
    name = "ext-des"
    option = "x"
    prefix = "_"
    suffix = ""
    min_length = 20
    salt_length = 8


    ## @classmethod
    ## def recognise_salt(c, s):
    ##     return False
