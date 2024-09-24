from ..structure import Algorithm


class OldPassword(Algorithm):
    """Pre-v4.1 MySQL, and also newer with the 'old-passwords' setting on"""

    name = "old-password"
    option = "o"
    prefix = ""
    suffix = ""
    min_length = 16


    @classmethod
    def final_prep(c):
        """[Override]"""
        # Pass it up the hierarchy
        Algorithm.final_prep()

        # http://djangosnippets.org/snippets/1508/
        global mysql_hash_password
        from hashpw.contrib.tback import mysql_hash_password


    def recognise(self, s):
        return False


    def hash(self, plaintext):
        return mysql_hash_password(plaintext)
