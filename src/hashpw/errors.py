class ShortSaltException(Exception):
    def __init__(self, msg="salt is too short"):
        Exception.__init__(self, msg)



class SaltPrefixException(Exception):
    pass



class BadAlgException(Exception):
    pass
