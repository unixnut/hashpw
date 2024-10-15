import base64


def base64encode(bits: bytes) -> str:
    """
    Returns a base64-encoded string using the standard password alphabet
    instead of the default or url-safe ones.
    """
    return base64.b64encode(bits, b'./').decode('ascii')


def base64decode(hash: str) -> bytes:
    """
    Extracts bits from a base64-encoded string using the standard password
    alphabet instead of the default or url-safe ones.
    """
    return base64.b64decode(hash, b'./')


def base64pad(hash: str) -> str:
    """
    Pad up a base64-encoded string to a multiple of 4 characters to make it
    valid for decoding.

    @see https://www.reddit.com/r/learnpython/comments/uen162/comment/i7004d9/ 
    """

    padding_len = len(hash) % 4
    return hash + (padding_len * '=')
