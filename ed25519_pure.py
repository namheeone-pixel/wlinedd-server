# -*- coding: utf-8 -*-
"""
ed25519_pure.py - 순수 파이썬 Ed25519 서명/검증 (RFC 8032)

외부 라이브러리 없이 동작합니다. 라이선스 명단(allowlist)을 관리자가 개인키로
서명하고, 배포된 프로그램은 공개키로 '진짜 관리자가 만든 명단인지' 검증합니다.
공개키는 프로그램에 넣어도 안전하고(공개용), 개인키는 관리자만 보관합니다.

쓰는 함수:
  keypair()                 -> (개인키 32B, 공개키 32B)
  publickey(개인키)          -> 공개키 32B
  sign(메시지, 개인키, 공개키) -> 서명 64B
  verify(메시지, 서명, 공개키) -> True/False
"""
import hashlib, os

_b = 256
_q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m): return hashlib.sha512(m).digest()
def _inv(x): return pow(x, _q - 2, _q)

_d = (-121665 * _inv(121666)) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0: x = (x * _I) % _q
    if x % 2 != 0: x = _q - x
    return x


_By = (4 * _inv(5)) % _q
_Bx = _xrecover(_By)
_B = (_Bx % _q, _By % _q, 1, (_Bx * _By) % _q)       # 확장 좌표 (X, Y, Z, T)


def _edwards(P, Q):
    x1, y1, z1, t1 = P; x2, y2, z2, t2 = Q
    a = ((y1 - x1) * (y2 - x2)) % _q
    b = ((y1 + x1) * (y2 + x2)) % _q
    c = (t1 * 2 * _d * t2) % _q
    dd = (z1 * 2 * z2) % _q
    e = b - a; f = dd - c; g = dd + c; h = b + a
    return ((e * f) % _q, (g * h) % _q, (f * g) % _q, (e * h) % _q)


def _scalarmult(P, e):
    Q = (0, 1, 1, 0)
    while e > 0:
        if e & 1: Q = _edwards(Q, P)
        P = _edwards(P, P); e >>= 1
    return Q


def _encodeint(y):
    return y.to_bytes(32, "little")


def _encodepoint(P):
    x, y, z, t = P
    zi = _inv(z); x = (x * zi) % _q; y = (y * zi) % _q
    bits = y & ((1 << 255) - 1)
    bits |= (x & 1) << 255
    return bits.to_bytes(32, "little")


def _bit(h, i): return (h[i // 8] >> (i % 8)) & 1


def publickey(sk):
    h = _H(sk)
    a = 2 ** (_b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, _b - 2))
    A = _scalarmult(_B, a)
    return _encodepoint(A)


def keypair():
    sk = os.urandom(32)
    return sk, publickey(sk)


def sign(msg, sk, pk=None):
    if pk is None: pk = publickey(sk)
    h = _H(sk)
    a = 2 ** (_b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, _b - 2))
    r = int.from_bytes(_H(h[32:] + msg), "little") % _L
    R = _scalarmult(_B, r)
    Rs = _encodepoint(R)
    k = int.from_bytes(_H(Rs + pk + msg), "little") % _L
    s = (r + k * a) % _L
    return Rs + _encodeint(s)


def _decodepoint(s):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if x & 1 != _bit(s, _b - 1): x = _q - x
    P = (x, y, 1, (x * y) % _q)
    return P


def _isoncurve(P):
    x, y, z, t = P
    return (z % _q != 0 and (x * y) % _q == (z * t) % _q and
            (y * y - x * x - z * z - _d * t * t) % _q == 0)


def verify(msg, sig, pk):
    """서명이 이 공개키로 만든 게 맞으면 True. 어떤 오류든 안전하게 False."""
    try:
        if len(sig) != 64 or len(pk) != 32: return False
        Rs = sig[:32]; s = int.from_bytes(sig[32:], "little")
        if s >= _L: return False
        R = _decodepoint(Rs); A = _decodepoint(pk)
        if not (_isoncurve(R) and _isoncurve(A)): return False
        k = int.from_bytes(_H(Rs + pk + msg), "little") % _L
        left = _scalarmult(_B, s)
        right = _edwards(R, _scalarmult(A, k))
        return _encodepoint(left) == _encodepoint(right)
    except Exception:
        return False
