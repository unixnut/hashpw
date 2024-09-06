import base64


def base64encode(bits):
    """
    Returns a base64-encoded string using the standard password alphabet
    instead of the default or url-safe ones.
    """
    return base64.b64encode(bits, b'./').decode('ascii')


def base64decode(hash):
    """Extracts bits from a base64-encoded string using the standard password alphabet
    instead of the default or url-safe ones."""
    return base64.b64decode(hash, b'./')
