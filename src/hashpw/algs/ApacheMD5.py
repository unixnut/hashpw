import passlib.hash

from ..structure import PLSaltedAlgorithm


class ApacheMD5(PLSaltedAlgorithm):
    name = "apache-md5"
    option = "a"
    prefix = "$apr1$"
    suffix = ""
    min_length = 37
    salt_length = 8


    def __init__(self, salt):
        super().__init__(salt)

        self.hasher = passlib.hash.apr_md5_crypt.using(salt=self.salt[6:])
