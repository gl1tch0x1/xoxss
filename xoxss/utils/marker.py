"""
Marker generation utility.
"""

import random
import string


def unique_token(length: int = 12) -> str:
    """Generate a unique random token."""
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))
