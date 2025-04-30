#!/usr/bin/env python
"""
Generates a Time-based One-Time Password (TOTP) and constructs an otpauth URI.

This function implements the TOTP algorithm as specified in RFC 6238. It takes a secret key and other parameters
to generate a one-time password valid for a specific time interval. Additionally, it constructs an otpauth URI
that can be used to configure TOTP in applications like Google Authenticator.

The function also supports parsing otpauth URIs to extract parameters and generate a TOTP code based on those parameters.

Args:
    secret (Optional[str]): The secret key used to generate the TOTP code. Can be a raw secret or an otpauth URI.
    interval (int): The time interval (in seconds) for which the TOTP code is valid. Defaults to 30.
    digits (int): The number of digits in the generated TOTP code. Defaults to 6.
    algorithm (str): The hashing algorithm used to generate the TOTP code. Defaults to "sha1".
    unix_time (int): The Unix timestamp to use for generating the TOTP code. If 0, the current time is used.
    label (str): The label to use in the otpauth URI. Defaults to an empty string.
    issuer (str): The issuer to use in the otpauth URI. Defaults to an empty string.
    **parameters (Dict[str, Any]): Additional parameters to include in the otpauth URI.

Returns:
    Optional[Dict[str, Any]]: A dictionary containing the generated TOTP code, otpauth URI, and other relevant parameters.
        - secret (str): The base32-encoded secret key used.
        - interval (int): The time interval used.
        - digits (int): The number of digits in the TOTP code.
        - algorithm (str): The hashing algorithm used.
        - original_secret (str): The original secret key provided.
        - time (int): The Unix timestamp used.
        - code (str): The generated TOTP code.
        - otpauth_uri (str): The constructed otpauth URI.
        - parameters (Dict[str, Any]): Any additional parameters provided.
        - verified (bool): Whether the generated code matches any of the provided parameters.
        - issuer (str): The issuer extracted from the otpauth URI or provided as an argument.

Raises:
    ValueError: If the secret is invalid or cannot be decoded.

Example:
    >>> result = totp(secret="JBSWY3DPEHPK3PXP", interval=30, digits=6, algorithm="sha1")
    >>> print(result)
    {
        "secret": "JBSWY3DPEHPK3PXP",
        "interval": 30,
        "digits": 6,
        "algorithm": "sha1",
        "original_secret": "JBSWY3DPEHPK3PXP",
        "time": 1681234567,
        "code": "123456",
        "otpauth_uri": "otpauth://totp/default:1681234567?secret=JBSWY3DPEHPK3PXP&interval=30&digits=6&algorithm=sha1",
        "parameters": {},
        "verified": False,
        "issuer": ""
    }

Note:
    - If the secret is an otpauth URI, the function will parse it and extract parameters.
    - The function assumes the secret is base32-encoded. If not, it will attempt to encode it.
    - The `pyotp` library is used to generate the TOTP code.

See Also:
    pyotp.TOTP: The TOTP class from the pyotp library used for generating TOTP codes.


生成基于时间的一次性密码（TOTP），并构造 otpauth URI。

该函数实现了 RFC 6238 中指定的 TOTP 算法。它接受一个密钥和其他参数，生成在特定时间间隔内有效的一次性密码。此外，它还构造了一个 otpauth URI，
可用于在 Google Authenticator 等应用程序中配置 TOTP。

该函数还支持解析 otpauth URI 以提取参数，并基于这些参数生成 TOTP 代码。

参数：
    secret (Optional[str])：用于生成 TOTP 代码的密钥。可以是原始密钥或 otpauth URI。
    interval (int)：TOTP 代码有效的时间间隔（以秒为单位）。默认为 30 秒。
    digits (int)：生成的 TOTP 代码的位数。默认为 6 位。
    algorithm (str)：用于生成 TOTP 代码的哈希算法。默认为 "sha1"。
    unix_time (int)：用于生成 TOTP 代码的 Unix 时间戳。如果为 0，则使用当前时间。
    label (str)：在 otpauth URI 中使用的标签。默认为空字符串。
    issuer (str)：在 otpauth URI 中使用的发行者。默认为空字符串。
    **parameters (Dict[str, Any])：在 otpauth URI 中包含的其他参数。

返回：
    返回值（Optional[Dict[str, Any]]）：一个字典，包含生成的 TOTP 代码、otpauth URI 以及其他相关参数。
        - secret (str)：使用的 base32 编码密钥。
        - interval (int)：使用的时间间隔。
        - digits (int)：TOTP 代码的位数。
        - algorithm (str)：使用的哈希算法。
        - original_secret (str)：提供的原始密钥。
        - time (int)：使用的 Unix 时间戳。
        - code (str)：生成的 TOTP 代码。
        - otpauth_uri (str)：构造的 otpauth URI。
        - parameters (Dict[str, Any])：提供的其他参数。
        - verified (bool)：生成的代码是否与提供的任何参数匹配。
        - issuer (str)：从 otpauth URI 中提取的发行者或作为参数提供的发行者。

异常：
    ValueError：如果密钥无效或无法解码。

示例：
    >>> result = totp(secret="JBSWY3DPEHPK3PXP", interval=30, digits=6, algorithm="sha1")
    >>> print(result)
    {
        "secret": "JBSWY3DPEHPK3PXP",
        "interval": 30,
        "digits": 6,
        "algorithm": "sha1",
        "original_secret": "JBSWY3DPEHPK3PXP",
        "time": 1681234567,
        "code": "123456",
        "otpauth_uri": "otpauth://totp/default:1681234567?secret=JBSWY3DPEHPK3PXP&interval=30&digits=6&algorithm=sha1",
        "parameters": {},
        "verified": False,
        "issuer": ""
    }

注意：
    - 如果密钥是 otpauth URI，该函数将解析它并提取参数。
    - 该函数假设密钥是 base32 编码的。如果不是，它将尝试对其进行编码。
    - 使用 `pyotp` 库生成 TOTP 代码。

参见：
    pyotp.TOTP：pyotp 库中用于生成 TOTP 代码的 TOTP 类。
"""


import hashlib
from time import time
from pyotp import TOTP
from typing import Dict, Any, Optional
from base64 import b32encode, b32decode
from urllib.parse import urlparse, parse_qs, urlunparse, quote, urlencode


def totp(
    secret: Optional[str] = None,
    interval: int = 30,
    digits: int = 6,
    algorithm: str = "sha1",
    utc: int = 0,
    label: str = str(),
    issuer: str = str(),
    **parameters: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    match secret:
        case None:
            return None
        case bytes():
            otp_secret = secret.decode("UTF-8")
        case _:
            otp_secret = str(secret)
    otp_data = {
        "secret": otp_secret,
        "issuer": issuer,
        "algorithm": algorithm,
        "digits": digits,
        "interval": interval,
        "original_secret": otp_secret,
        "otpauth_uri": None,
        "code": None,
        "parameters": parameters,
        "utc": utc or int(time()),
        "verified": False
    }
    if "otpauth" in otp_secret:
        otp_params = parse_qs(urlparse(otp_secret).query)
        otp_extracted = {k: v[0] for k, v in otp_params.items()}
        otp_data.update({
            "utc": int(otp_extracted.get("utc", otp_data["utc"])),
            "secret": otp_extracted.get("secret", otp_data["secret"]),
            "issuer": otp_extracted.get("issuer", otp_data["issuer"]),
            "algorithm": otp_extracted.get("algorithm", otp_data["algorithm"]),
            "digits": int(otp_extracted.get("digits", otp_data["digits"])),
            "interval": int(otp_extracted.get("period", otp_data["interval"]))
        })
    try:
        b32decode(otp_data["secret"])
    except:
        otp_data["secret"] = b32encode(
            otp_data["secret"].encode("UTF-8")).decode("UTF-8")
    otp_data["secret"] = otp_data["secret"].rstrip("=")
    otp_code = TOTP(
        otp_data["secret"],
        interval=otp_data["interval"],
        digits=otp_data["digits"],
        digest=getattr(hashlib, otp_data["algorithm"].lower())
    ).at(otp_data["utc"])
    otp_label = label or f"default:{otp_data['utc']}"
    otp_data.update({
        "code": otp_code,
        "verified": otp_code in parameters.values(),
        "otpauth_uri": urlunparse(
            (
                "otpauth",
                "totp",
                f"/{quote(otp_label, safe=str())}",
                str(),
                urlencode(otp_data, quote_via=quote),
                str()
            )
        )
    })
    return otp_data
