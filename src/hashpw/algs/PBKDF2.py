import passlib.hash
import passlib.utils

from ..structure import PLSaltedAlgorithm


class PBKDF2(PLSaltedAlgorithm):
    name = "django-pbkdf2"
    option = "d"
    prefix = "pbkdf2_sha256"
    suffix = ""
    min_length = 70     # prefix + '$' + rounds(2 chars) + '$' + 44 chars


    # This can't be a @classmethod because parent classes have to work with its properties
    @staticmethod
    def init(c, *, long_salt):
        """Ensure that check_salt() checks the length of the whole hash."""

        if long_salt:
            c.salt_length = 16
        else:
            c.salt_length = 8
        PLSaltedAlgorithm.init(c)

        ## c.rounds=260000
        c.rounds=300000
        c.salt_prefix_len = 21    # pbkdf2_sha256$260000$
        c.comp_len = c.salt_prefix_len + c.salt_length


    @classmethod
    def generate_salt(c):
        """
        Calculates an encoded salt string, including prefix, for this algorithm.

        [Override]
        """

        salt_chars = passlib.utils.getrandstr(passlib.utils.rng,
                                              passlib.hash.django_pbkdf2_sha256.salt_chars,
                                              c.salt_length)
        s = "%s$%d$%s$" % (c.prefix, c.rounds, salt_chars)
        return s


    def __init__(self, salt):
        super().__init__(salt)

        ## print(self.salt[self.salt_prefix_len:])
        startidx = self.salt_prefix_len
        endidx =   self.salt_prefix_len + self.salt_length
        info = { 'salt':   self.salt[startidx:endidx],
                 'rounds': self.rounds }
        self.hasher = passlib.hash.django_pbkdf2_sha256.using(**info)
