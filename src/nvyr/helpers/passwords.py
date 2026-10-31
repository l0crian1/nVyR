"""Credential ingress: salted Linux yescrypt, with no subprocess password arguments."""

import ctypes
import ctypes.util
from copy import deepcopy
import os
import threading

from nvyr.errors import ValidationError, RouterError

_lock = threading.Lock()


def hash_password(value):
    if not isinstance(value, str) or not value or len(value.encode('utf-8')) > 512 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValidationError('Password must contain 1–512 UTF-8 bytes without control characters')

    # libcrypt is already part of Debian authentication. Python 3.13 removed crypt.
    library = ctypes.CDLL(ctypes.util.find_library('crypt') or 'libcrypt.so.1')
    library.crypt_gensalt.argtypes = [ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_int]
    library.crypt_gensalt.restype = ctypes.c_char_p
    library.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    library.crypt.restype = ctypes.c_char_p
    entropy = os.urandom(32)

    with _lock:  # Both APIs return library-owned static buffers.
        salt = library.crypt_gensalt(b'$y$', 5, entropy, len(entropy))
        result = library.crypt(value.encode('utf-8'), salt) if salt else None
        if not result or not result.startswith(b'$y$'):
            raise RouterError('Linux yescrypt password hashing failed')

        return result.decode('ascii')


def normalize(configuration):
    """JSON loads use the same credential ingress as individual set commands."""
    configuration = deepcopy(configuration)
    if not isinstance(configuration, dict):
        return configuration

    system = configuration.get('system', {})
    login = system.get('login', {}) if isinstance(system, dict) else {}
    users = login.get('user', {}) if isinstance(login, dict) else {}

    for user in users.values() if isinstance(users, dict) else ():
        auth = user.get('authentication', {}) if isinstance(user, dict) else {}
        if isinstance(auth, dict) and 'plaintext-password' in auth:
            if 'encrypted-password' in auth:
                raise ValidationError('Specify either plaintext-password or encrypted-password, not both')

            auth['encrypted-password'] = hash_password(auth.pop('plaintext-password'))

    return configuration


def sensitive_line(text):
    # Conservative for abbreviations, malformed quoting and relative edit paths.
    # False positives only omit history; false negatives would disclose secrets.
    import re

    return any(word and ('plaintext-password'.startswith(word) or 'encrypted-password'.startswith(word))
               for word in re.split(r'[\s\'"|]+', text))
