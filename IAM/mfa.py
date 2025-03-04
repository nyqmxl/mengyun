#!/usr/bin/env python


def totp(
    secret: str = "",
    interval: int = 30,
    digits: int = 6,
    algorithm: str = "sha1",
    unix_time: int = 0,
    label: str = "",
    issuer: str = "",
    parameters: dict = dict()
) -> dict:
    import hashlib
    from time import time
    from pyotp import TOTP
    from binascii import Error
    from base64 import b32encode, b32decode
    from urllib.parse import urlparse, parse_qs, urlunparse, quote, urlencode
    match (secret):
        case None:
            return None
        case bytes():
            secret = secret.decode("UTF-8")
        case _:
            secret = str(secret)
    if "otpauth" in secret:
        uri_components = urlparse(secret)
        uri_params = parse_qs(uri_components.query)
        extracted_params = {k: v[0] for k, v in uri_params.items()}
        unix_time = extracted_params.get("time", unix_time or int(time()))
        secret = extracted_params.get("secret", secret)
        interval = int(extracted_params.get("period", interval))
        digits = int(extracted_params.get("digits", digits))
        algorithm = extracted_params.get("algorithm", algorithm)
        issuer = extracted_params.get("issuer", issuer)
    unix_time = unix_time or int(time())
    original_secret = secret
    try:
        b32decode(secret)
    except (Error, TypeError):
        secret = b32encode(secret.encode("UTF-8")).decode("UTF-8")
    code = TOTP(
        secret,
        interval=int(interval) or 30,
        digits=int(digits) or 6,
        digest=getattr(hashlib, algorithm.lower())
    ).at(unix_time)
    data = {
        "secret": secret,
        "interval": interval,
        "digits": digits,
        "algorithm": algorithm,
        "key": original_secret,
        "time": unix_time,
        "code": code
    }
    data.update({"issuer": issuer})
    label = label or f"default:{data['time']}"
    url = urlunparse((
        "otpauth",
        "totp",
        f"/{quote(label, safe=str())}",
        "",
        urlencode(data, quote_via=quote),
        ""
    ))
    data = {
        "otpauth_uri": url,
        "parameters": parameters,
        "verified": code in parameters.values(),
        "secret": secret,
        "interval": interval,
        "digits": digits,
        "algorithm": algorithm,
        "original_secret": original_secret,
        "time": unix_time,
        "code": code
    }
    return data
