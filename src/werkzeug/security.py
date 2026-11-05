# -*- coding: utf-8 -*-
"""
    werkzeug.security
    ~~~~~~~~~~~~~~~~~

    Security related helpers such as secure password hashing tools.

    :copyright: 2007 Pallets
    :license: BSD-3-Clause
"""
import codecs
import hashlib
import hmac
import os
import posixpath
import sys
from random import SystemRandom
from struct import Struct

from ._compat import izip
from ._compat import PY2
from ._compat import range_type
from ._compat import text_type
from ._compat import to_bytes
from ._compat import to_native

SALT_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
DEFAULT_PBKDF2_ITERATIONS = 150000

_pack_int = Struct(">I").pack
_builtin_safe_str_cmp = getattr(hmac, "compare_digest", None)
_sys_rng = SystemRandom()
_os_alt_seps = list(
    sep for sep in [os.path.sep, os.path.altsep] if sep not in (None, "/")
)
# https://chrisdenton.github.io/omnipath/Special%20Dos%20Device%20Names.html
# The superscript digits are U+00B9, U+00B2 and U+00B3.
_windows_device_files = frozenset(
    [u"AUX", u"CON", u"CONIN$", u"CONOUT$", u"NUL", u"PRN"]
    + [u"COM" + c for c in u"123456789\u00b9\u00b2\u00b3"]
    + [u"LPT" + c for c in u"123456789\u00b9\u00b2\u00b3"]
)


def pbkdf2_hex(
    data, salt, iterations=DEFAULT_PBKDF2_ITERATIONS, keylen=None, hashfunc=None
):
    """Like :func:`pbkdf2_bin`, but returns a hex-encoded string.

    .. versionadded:: 0.9

    :param data: the data to derive.
    :param salt: the salt for the derivation.
    :param iterations: the number of iterations.
    :param keylen: the length of the resulting key.  If not provided,
                   the digest size will be used.
    :param hashfunc: the hash function to use.  This can either be the
                     string name of a known hash function, or a function
                     from the hashlib module.  Defaults to sha256.
    """
    rv = pbkdf2_bin(data, salt, iterations, keylen, hashfunc)
    return to_native(codecs.encode(rv, "hex_codec"))


def pbkdf2_bin(
    data, salt, iterations=DEFAULT_PBKDF2_ITERATIONS, keylen=None, hashfunc=None
):
    """Returns a binary digest for the PBKDF2 hash algorithm of `data`
    with the given `salt`. It iterates `iterations` times and produces a
    key of `keylen` bytes. By default, SHA-256 is used as hash function;
    a different hashlib `hashfunc` can be provided.

    .. versionadded:: 0.9

    :param data: the data to derive.
    :param salt: the salt for the derivation.
    :param iterations: the number of iterations.
    :param keylen: the length of the resulting key.  If not provided
                   the digest size will be used.
    :param hashfunc: the hash function to use.  This can either be the
                     string name of a known hash function or a function
                     from the hashlib module.  Defaults to sha256.
    """
    if not hashfunc:
        hashfunc = "sha256"

    data = to_bytes(data)
    salt = to_bytes(salt)

    if callable(hashfunc):
        _test_hash = hashfunc()
        hash_name = getattr(_test_hash, "name", None)
    else:
        hash_name = hashfunc
    return hashlib.pbkdf2_hmac(hash_name, data, salt, iterations, keylen)


def safe_str_cmp(a, b):
    """This function compares strings in somewhat constant time.  This
    requires that the length of at least one string is known in advance.

    Returns `True` if the two strings are equal, or `False` if they are not.

    .. versionadded:: 0.7
    """
    if isinstance(a, text_type):
        a = a.encode("utf-8")
    if isinstance(b, text_type):
        b = b.encode("utf-8")

    if _builtin_safe_str_cmp is not None:
        return _builtin_safe_str_cmp(a, b)

    if len(a) != len(b):
        return False

    rv = 0
    if PY2:
        for x, y in izip(a, b):
            rv |= ord(x) ^ ord(y)
    else:
        for x, y in izip(a, b):
            rv |= x ^ y

    return rv == 0


def gen_salt(length):
    """Generate a random string of SALT_CHARS with specified ``length``."""
    if length <= 0:
        raise ValueError("Salt length must be positive")
    return "".join(_sys_rng.choice(SALT_CHARS) for _ in range_type(length))


def _hash_internal(method, salt, password):
    """Internal password hash helper.  Supports plaintext without salt,
    unsalted and salted passwords.  In case salted passwords are used
    hmac is used.
    """
    if method == "plain":
        return password, method

    if isinstance(password, text_type):
        password = password.encode("utf-8")

    if method.startswith("pbkdf2:"):
        args = method[7:].split(":")
        if len(args) not in (1, 2):
            raise ValueError("Invalid number of arguments for PBKDF2")
        method = args.pop(0)
        iterations = args and int(args[0] or 0) or DEFAULT_PBKDF2_ITERATIONS
        is_pbkdf2 = True
        actual_method = "pbkdf2:%s:%d" % (method, iterations)
    else:
        is_pbkdf2 = False
        actual_method = method

    if is_pbkdf2:
        if not salt:
            raise ValueError("Salt is required for PBKDF2")
        rv = pbkdf2_hex(password, salt, iterations, hashfunc=method)
    elif salt:
        if isinstance(salt, text_type):
            salt = salt.encode("utf-8")
        mac = _create_mac(salt, password, method)
        rv = mac.hexdigest()
    else:
        rv = hashlib.new(method, password).hexdigest()
    return rv, actual_method


def _create_mac(key, msg, method):
    if callable(method):
        return hmac.HMAC(key, msg, method)

    def hashfunc(d=b""):
        return hashlib.new(method, d)

    # Python 2.7 used ``hasattr(digestmod, '__call__')``
    # to detect if hashfunc is callable
    hashfunc.__call__ = hashfunc
    return hmac.HMAC(key, msg, hashfunc)


def generate_password_hash(password, method="pbkdf2:sha256", salt_length=8):
    """Hash a password with the given method and salt with a string of
    the given length. The format of the string returned includes the method
    that was used so that :func:`check_password_hash` can check the hash.

    The format for the hashed string looks like this::

        method$salt$hash

    This method can **not** generate unsalted passwords but it is possible
    to set param method='plain' in order to enforce plaintext passwords.
    If a salt is used, hmac is used internally to salt the password.

    If PBKDF2 is wanted it can be enabled by setting the method to
    ``pbkdf2:method:iterations`` where iterations is optional::

        pbkdf2:sha256:80000$salt$hash
        pbkdf2:sha256$salt$hash

    :param password: the password to hash.
    :param method: the hash method to use (one that hashlib supports). Can
                   optionally be in the format ``pbkdf2:<method>[:iterations]``
                   to enable PBKDF2.
    :param salt_length: the length of the salt in letters.
    """
    salt = gen_salt(salt_length) if method != "plain" else ""
    h, actual_method = _hash_internal(method, salt, password)
    return "%s$%s$%s" % (actual_method, salt, h)


def check_password_hash(pwhash, password):
    """check a password against a given salted and hashed password value.
    In order to support unsalted legacy passwords this method supports
    plain text passwords, md5 and sha1 hashes (both salted and unsalted).

    Returns `True` if the password matched, `False` otherwise.

    :param pwhash: a hashed string like returned by
                   :func:`generate_password_hash`.
    :param password: the plaintext password to compare against the hash.
    """
    if pwhash.count("$") < 2:
        return False
    method, salt, hashval = pwhash.split("$", 2)
    return safe_str_cmp(_hash_internal(method, salt, password)[0], hashval)


def _is_windows_device_name(segment):
    """Check if one path segment names a Windows special device such as
    ``CON``, ``NUL`` or ``COM1``, regardless of an alternate data stream
    marker, extension or surrounding spaces.
    """
    if isinstance(segment, bytes):
        # Python 2 native strings are passed to the Windows file APIs in
        # the filesystem (ANSI) encoding, so decode the same way.
        segment = segment.decode(sys.getfilesystemencoding() or "utf-8", "replace")

    name = segment.partition(u":")[0].partition(u".")[0].strip().upper()
    return name in _windows_device_files


def safe_join(directory, *pathnames):
    """Safely join zero or more untrusted path components to a trusted base
    directory to avoid escaping the base directory. Return ``None`` if the
    path is not safe.

    The untrusted path is assumed to be from/for a URL, such as for serving
    files. Therefore, it should only use the forward slash ``/`` path
    separator, and will be joined using that separator. On Windows, the
    backslash ``\\`` separator is not allowed.

    On Windows, special device names such as ``CON`` and ``NUL`` are not
    allowed in any segment, regardless of extension, surrounding spaces or
    an alternate data stream marker.

    :param directory: The trusted base directory.
    :param pathnames: The untrusted path components relative to the
        base directory.
    :return: A safe path, otherwise ``None``.

    .. versionchanged:: 1.0.1.post1
        Security backports from Werkzeug 2.1.0 (an empty ``directory``
        stays relative), 3.0.6 (paths starting with ``/`` are rejected on
        Windows, GHSA-f9vj-2wh5-fj8j), 3.1.4, 3.1.5, 3.1.6 and 3.1.9
        (Windows special device names are rejected, GHSA-hgf8-39gv-g3f2,
        GHSA-87hc-h4r5-73f7, GHSA-29vq-49wr-vm6x, GHSA-g6x2-hccm-hh4m).
    """
    if not directory:
        # Ensure we end up with ./path if directory="" is given,
        # otherwise the first untrusted part could become trusted.
        directory = "."

    parts = [directory]

    for filename in pathnames:
        if not filename:
            continue

        filename = posixpath.normpath(filename)

        if (
            os.path.isabs(filename)
            # ntpath.isabs doesn't catch UNC-like "//server/share"
            or filename.startswith("/")
            or filename == ".."
            or filename.startswith("../")
            or any(sep in filename for sep in _os_alt_seps)
            or (
                os.name == "nt"
                and any(_is_windows_device_name(p) for p in filename.split("/"))
            )
        ):
            return None

        parts.append(filename)

    return posixpath.join(*parts)
