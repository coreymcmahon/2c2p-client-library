/*!
 * 2c2p End-to-End Encryption Library
 * https://www.2c2p.com
 * Copyright (c) 2c2p
 * v1.6.6
 *
 * JSBN
 * Copyright (c) 2005  Tom Wu
 * Licensed under the BSD License.
 * http://www-cs-students.stanford.edu/~tjw/jsbn/LICENSE
 *
 * ASN.1 JavaScript decoder
 * Copyright (c) 2008-2009 Lapo Luchini <lapo@lapo.it>
 * Licensed under the ISC License.
 * http://opensource.org/licenses/ISC
 *
 * Gibberish AES
 * Copyright: Mark Percival 2008 - http://markpercival.us
 * License under the MIT
 * http://opensource.org/licenses/MIT
 */

function BigInteger(t, r, e) {
    null != t && ("number" == typeof t ? this.fromNumber(t, r, e) : null == r && "string" != typeof t ? this.fromString(t, 256) : this.fromString(t, r))
}

function nbi() {
    return new BigInteger(null)
}

function am1(t, r, e, n, i, o) {
    for (; --o >= 0;) {
        var s = r * this[t++] + e[n] + i;
        i = Math.floor(s / 67108864), e[n++] = 67108863 & s
    }
    return i
}

function am2(t, r, e, n, i, o) {
    for (var s = 32767 & r, a = r >> 15; --o >= 0;) {
        var h = 32767 & this[t],
            u = this[t++] >> 15,
            c = a * h + u * s;
        h = s * h + ((32767 & c) << 15) + e[n] + (1073741823 & i), i = (h >>> 30) + (c >>> 15) + a * u + (i >>> 30), e[n++] = 1073741823 & h
    }
    return i
}

function am3(t, r, e, n, i, o) {
    for (var s = 16383 & r, a = r >> 14; --o >= 0;) {
        var h = 16383 & this[t],
            u = this[t++] >> 14,
            c = a * h + u * s;
        h = s * h + ((16383 & c) << 14) + e[n] + i, i = (h >> 28) + (c >> 14) + a * u, e[n++] = 268435455 & h
    }
    return i
}

function int2char(t) {
    return BI_RM.charAt(t)
}

function intAt(t, r) {
    var e = BI_RC[t.charCodeAt(r)];
    return null == e ? -1 : e
}

function bnpCopyTo(t) {
    for (var r = this.t - 1; r >= 0; --r) t[r] = this[r];
    t.t = this.t, t.s = this.s
}

function bnpFromInt(t) {
    this.t = 1, this.s = 0 > t ? -1 : 0, t > 0 ? this[0] = t : -1 > t ? this[0] = t + this.DV : this.t = 0
}

function nbv(t) {
    var r = nbi();
    return r.fromInt(t), r
}

function bnpFromString(t, r) {
    var e;
    if (16 == r) e = 4;
    else if (8 == r) e = 3;
    else if (256 == r) e = 8;
    else if (2 == r) e = 1;
    else if (32 == r) e = 5;
    else {
        if (4 != r) return void this.fromRadix(t, r);
        e = 2
    }
    this.t = 0, this.s = 0;
    for (var n = t.length, i = !1, o = 0; --n >= 0;) {
        var s = 8 == e ? 255 & t[n] : intAt(t, n);
        0 > s ? "-" == t.charAt(n) && (i = !0) : (i = !1, 0 == o ? this[this.t++] = s : o + e > this.DB ? (this[this.t - 1] |= (s & (1 << this.DB - o) - 1) << o, this[this.t++] = s >> this.DB - o) : this[this.t - 1] |= s << o, o += e, o >= this.DB && (o -= this.DB))
    }
    8 == e && 0 != (128 & t[0]) && (this.s = -1, o > 0 && (this[this.t - 1] |= (1 << this.DB - o) - 1 << o)), this.clamp(), i && BigInteger.ZERO.subTo(this, this)
}

function bnpClamp() {
    for (var t = this.s & this.DM; this.t > 0 && this[this.t - 1] == t;) --this.t
}

function bnToString(t) {
    if (this.s < 0) return "-" + this.negate().toString(t);
    var r;
    if (16 == t) r = 4;
    else if (8 == t) r = 3;
    else if (2 == t) r = 1;
    else if (32 == t) r = 5;
    else {
        if (4 != t) return this.toRadix(t);
        r = 2
    }
    var e, n = (1 << r) - 1,
        i = !1,
        o = "",
        s = this.t,
        a = this.DB - s * this.DB % r;
    if (s-- > 0)
        for (a < this.DB && (e = this[s] >> a) > 0 && (i = !0, o = int2char(e)); s >= 0;) r > a ? (e = (this[s] & (1 << a) - 1) << r - a, e |= this[--s] >> (a += this.DB - r)) : (e = this[s] >> (a -= r) & n, 0 >= a && (a += this.DB, --s)), e > 0 && (i = !0), i && (o += int2char(e));
    return i ? o : "0"
}

function bnNegate() {
    var t = nbi();
    return BigInteger.ZERO.subTo(this, t), t
}

function bnAbs() {
    return this.s < 0 ? this.negate() : this
}

function bnCompareTo(t) {
    var r = this.s - t.s;
    if (0 != r) return r;
    var e = this.t;
    if (r = e - t.t, 0 != r) return this.s < 0 ? -r : r;
    for (; --e >= 0;)
        if (0 != (r = this[e] - t[e])) return r;
    return 0
}

function nbits(t) {
    var r, e = 1;
    return 0 != (r = t >>> 16) && (t = r, e += 16), 0 != (r = t >> 8) && (t = r, e += 8), 0 != (r = t >> 4) && (t = r, e += 4), 0 != (r = t >> 2) && (t = r, e += 2), 0 != (r = t >> 1) && (t = r, e += 1), e
}

function bnBitLength() {
    return this.t <= 0 ? 0 : this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ this.s & this.DM)
}

function bnpDLShiftTo(t, r) {
    var e;
    for (e = this.t - 1; e >= 0; --e) r[e + t] = this[e];
    for (e = t - 1; e >= 0; --e) r[e] = 0;
    r.t = this.t + t, r.s = this.s
}

function bnpDRShiftTo(t, r) {
    for (var e = t; e < this.t; ++e) r[e - t] = this[e];
    r.t = Math.max(this.t - t, 0), r.s = this.s
}

function bnpLShiftTo(t, r) {
    var e, n = t % this.DB,
        i = this.DB - n,
        o = (1 << i) - 1,
        s = Math.floor(t / this.DB),
        a = this.s << n & this.DM;
    for (e = this.t - 1; e >= 0; --e) r[e + s + 1] = this[e] >> i | a, a = (this[e] & o) << n;
    for (e = s - 1; e >= 0; --e) r[e] = 0;
    r[s] = a, r.t = this.t + s + 1, r.s = this.s, r.clamp()
}

function bnpRShiftTo(t, r) {
    r.s = this.s;
    var e = Math.floor(t / this.DB);
    if (e >= this.t) return void(r.t = 0);
    var n = t % this.DB,
        i = this.DB - n,
        o = (1 << n) - 1;
    r[0] = this[e] >> n;
    for (var s = e + 1; s < this.t; ++s) r[s - e - 1] |= (this[s] & o) << i, r[s - e] = this[s] >> n;
    n > 0 && (r[this.t - e - 1] |= (this.s & o) << i), r.t = this.t - e, r.clamp()
}

function bnpSubTo(t, r) {
    for (var e = 0, n = 0, i = Math.min(t.t, this.t); i > e;) n += this[e] - t[e], r[e++] = n & this.DM, n >>= this.DB;
    if (t.t < this.t) {
        for (n -= t.s; e < this.t;) n += this[e], r[e++] = n & this.DM, n >>= this.DB;
        n += this.s
    } else {
        for (n += this.s; e < t.t;) n -= t[e], r[e++] = n & this.DM, n >>= this.DB;
        n -= t.s
    }
    r.s = 0 > n ? -1 : 0, -1 > n ? r[e++] = this.DV + n : n > 0 && (r[e++] = n), r.t = e, r.clamp()
}

function bnpMultiplyTo(t, r) {
    var e = this.abs(),
        n = t.abs(),
        i = e.t;
    for (r.t = i + n.t; --i >= 0;) r[i] = 0;
    for (i = 0; i < n.t; ++i) r[i + e.t] = e.am(0, n[i], r, i, 0, e.t);
    r.s = 0, r.clamp(), this.s != t.s && BigInteger.ZERO.subTo(r, r)
}

function bnpSquareTo(t) {
    for (var r = this.abs(), e = t.t = 2 * r.t; --e >= 0;) t[e] = 0;
    for (e = 0; e < r.t - 1; ++e) {
        var n = r.am(e, r[e], t, 2 * e, 0, 1);
        (t[e + r.t] += r.am(e + 1, 2 * r[e], t, 2 * e + 1, n, r.t - e - 1)) >= r.DV && (t[e + r.t] -= r.DV, t[e + r.t + 1] = 1)
    }
    t.t > 0 && (t[t.t - 1] += r.am(e, r[e], t, 2 * e, 0, 1)), t.s = 0, t.clamp()
}

function bnpDivRemTo(t, r, e) {
    var n = t.abs();
    if (!(n.t <= 0)) {
        var i = this.abs();
        if (i.t < n.t) return null != r && r.fromInt(0), void(null != e && this.copyTo(e));
        null == e && (e = nbi());
        var o = nbi(),
            s = this.s,
            a = t.s,
            h = this.DB - nbits(n[n.t - 1]);
        h > 0 ? (n.lShiftTo(h, o), i.lShiftTo(h, e)) : (n.copyTo(o), i.copyTo(e));
        var u = o.t,
            c = o[u - 1];
        if (0 != c) {
            var f = c * (1 << this.F1) + (u > 1 ? o[u - 2] >> this.F2 : 0),
                p = this.FV / f,
                g = (1 << this.F1) / f,
                l = 1 << this.F2,
                d = e.t,
                b = d - u,
                v = null == r ? nbi() : r;
            for (o.dlShiftTo(b, v), e.compareTo(v) >= 0 && (e[e.t++] = 1, e.subTo(v, e)), BigInteger.ONE.dlShiftTo(u, v), v.subTo(o, o); o.t < u;) o[o.t++] = 0;
            for (; --b >= 0;) {
                var m = e[--d] == c ? this.DM : Math.floor(e[d] * p + (e[d - 1] + l) * g);
                if ((e[d] += o.am(0, m, e, b, 0, u)) < m)
                    for (o.dlShiftTo(b, v), e.subTo(v, e); e[d] < --m;) e.subTo(v, e)
            }
            null != r && (e.drShiftTo(u, r), s != a && BigInteger.ZERO.subTo(r, r)), e.t = u, e.clamp(), h > 0 && e.rShiftTo(h, e), 0 > s && BigInteger.ZERO.subTo(e, e)
        }
    }
}

function bnMod(t) {
    var r = nbi();
    return this.abs().divRemTo(t, null, r), this.s < 0 && r.compareTo(BigInteger.ZERO) > 0 && t.subTo(r, r), r
}

function Classic(t) {
    this.m = t
}

function cConvert(t) {
    return t.s < 0 || t.compareTo(this.m) >= 0 ? t.mod(this.m) : t
}

function cRevert(t) {
    return t
}

function cReduce(t) {
    t.divRemTo(this.m, null, t)
}

function cMulTo(t, r, e) {
    t.multiplyTo(r, e), this.reduce(e)
}

function cSqrTo(t, r) {
    t.squareTo(r), this.reduce(r)
}

function bnpInvDigit() {
    if (this.t < 1) return 0;
    var t = this[0];
    if (0 == (1 & t)) return 0;
    var r = 3 & t;
    return r = r * (2 - (15 & t) * r) & 15, r = r * (2 - (255 & t) * r) & 255, r = r * (2 - ((65535 & t) * r & 65535)) & 65535, r = r * (2 - t * r % this.DV) % this.DV, r > 0 ? this.DV - r : -r
}

function Montgomery(t) {
    this.m = t, this.mp = t.invDigit(), this.mpl = 32767 & this.mp, this.mph = this.mp >> 15, this.um = (1 << t.DB - 15) - 1, this.mt2 = 2 * t.t
}

function montConvert(t) {
    var r = nbi();
    return t.abs().dlShiftTo(this.m.t, r), r.divRemTo(this.m, null, r), t.s < 0 && r.compareTo(BigInteger.ZERO) > 0 && this.m.subTo(r, r), r
}

function montRevert(t) {
    var r = nbi();
    return t.copyTo(r), this.reduce(r), r
}

function montReduce(t) {
    for (; t.t <= this.mt2;) t[t.t++] = 0;
    for (var r = 0; r < this.m.t; ++r) {
        var e = 32767 & t[r],
            n = e * this.mpl + ((e * this.mph + (t[r] >> 15) * this.mpl & this.um) << 15) & t.DM;
        for (e = r + this.m.t, t[e] += this.m.am(0, n, t, r, 0, this.m.t); t[e] >= t.DV;) t[e] -= t.DV, t[++e]++
    }
    t.clamp(), t.drShiftTo(this.m.t, t), t.compareTo(this.m) >= 0 && t.subTo(this.m, t)
}

function montSqrTo(t, r) {
    t.squareTo(r), this.reduce(r)
}

function montMulTo(t, r, e) {
    t.multiplyTo(r, e), this.reduce(e)
}

function bnpIsEven() {
    return 0 == (this.t > 0 ? 1 & this[0] : this.s)
}

function bnpExp(t, r) {
    if (t > 4294967295 || 1 > t) return BigInteger.ONE;
    var e = nbi(),
        n = nbi(),
        i = r.convert(this),
        o = nbits(t) - 1;
    for (i.copyTo(e); --o >= 0;)
        if (r.sqrTo(e, n), (t & 1 << o) > 0) r.mulTo(n, i, e);
        else {
            var s = e;
            e = n, n = s
        }
    return r.revert(e)
}

function bnModPowInt(t, r) {
    var e;
    return e = 256 > t || r.isEven() ? new Classic(r) : new Montgomery(r), this.exp(t, e)
}

function Arcfour() {
    this.i = 0, this.j = 0, this.S = new Array
}

function ARC4init(t) {
    var r, e, n;
    for (r = 0; 256 > r; ++r) this.S[r] = r;
    for (e = 0, r = 0; 256 > r; ++r) e = e + this.S[r] + t[r % t.length] & 255, n = this.S[r], this.S[r] = this.S[e], this.S[e] = n;
    this.i = 0, this.j = 0
}

function ARC4next() {
    var t;
    return this.i = this.i + 1 & 255, this.j = this.j + this.S[this.i] & 255, t = this.S[this.i], this.S[this.i] = this.S[this.j], this.S[this.j] = t, this.S[t + this.S[this.i] & 255]
}

function prng_newstate() {
    return new Arcfour
}

function rng_seed_int(t) {
    rng_pool[rng_pptr++] ^= 255 & t, rng_pool[rng_pptr++] ^= t >> 8 & 255, rng_pool[rng_pptr++] ^= t >> 16 & 255, rng_pool[rng_pptr++] ^= t >> 24 & 255, rng_pptr >= rng_psize && (rng_pptr -= rng_psize)
}

function rng_seed_time() {
    rng_seed_int((new Date).getTime())
}

function rng_get_byte() {
    if (null == rng_state) {
        for (rng_seed_time(), rng_state = prng_newstate(), rng_state.init(rng_pool), rng_pptr = 0; rng_pptr < rng_pool.length; ++rng_pptr) rng_pool[rng_pptr] = 0;
        rng_pptr = 0
    }
    return rng_state.next()
}

function rng_get_bytes(t) {
    var r;
    for (r = 0; r < t.length; ++r) t[r] = rng_get_byte()
}

function SecureRandom() {}

function parseBigInt(t, r) {
    return new BigInteger(t, r)
}

function linebrk(t, r) {
    for (var e = "", n = 0; n + r < t.length;) e += t.substring(n, n + r) + "\n", n += r;
    return e + t.substring(n, t.length)
}

function byte2Hex(t) {
    return 16 > t ? "0" + t.toString(16) : t.toString(16)
}

function pkcs1pad2(t, r) {
    if (r < t.length + 11) return alert("Message too long for RSA"), null;
    for (var e = new Array, n = t.length - 1; n >= 0 && r > 0;) {
        var i = t.charCodeAt(n--);
        128 > i ? e[--r] = i : i > 127 && 2048 > i ? (e[--r] = 63 & i | 128, e[--r] = i >> 6 | 192) : (e[--r] = 63 & i | 128, e[--r] = i >> 6 & 63 | 128, e[--r] = i >> 12 | 224)
    }
    e[--r] = 0;
    for (var o = new SecureRandom, s = new Array; r > 2;) {
        for (s[0] = 0; 0 == s[0];) o.nextBytes(s);
        e[--r] = s[0]
    }
    return e[--r] = 2, e[--r] = 0, new BigInteger(e)
}

function RSAKey() {
    this.n = null, this.e = 0, this.d = null, this.p = null, this.q = null, this.dmp1 = null, this.dmq1 = null, this.coeff = null
}

function RSASetPublic(t, r) {
    null != t && null != r && t.length > 0 && r.length > 0 ? (this.n = parseBigInt(t, 16), this.e = parseInt(r, 16)) : alert("Invalid RSA public key")
}

function RSADoPublic(t) {
    return t.modPowInt(this.e, this.n)
}

function RSAEncrypt(t) {
    var r = pkcs1pad2(t, this.n.bitLength() + 7 >> 3);
    if (null == r) return null;
    var e = this.doPublic(r);
    if (null == e) return null;
    var n = e.toString(16);
    return 0 == (1 & n.length) ? n : "0" + n
}

function hex2b64(t) {
    var r, e, n = "";
    for (r = 0; r + 3 <= t.length; r += 3) e = parseInt(t.substring(r, r + 3), 16), n += b64map.charAt(e >> 6) + b64map.charAt(63 & e);
    for (r + 1 == t.length ? (e = parseInt(t.substring(r, r + 1), 16), n += b64map.charAt(e << 2)) : r + 2 == t.length && (e = parseInt(t.substring(r, r + 2), 16), n += b64map.charAt(e >> 2) + b64map.charAt((3 & e) << 4));
        (3 & n.length) > 0;) n += b64padchar;
    return n
}

function b64tohex(t) {
    var r, e, n = "",
        i = 0;
    for (r = 0; r < t.length && t.charAt(r) != b64padchar; ++r) v = b64map.indexOf(t.charAt(r)), 0 > v || (0 == i ? (n += int2char(v >> 2), e = 3 & v, i = 1) : 1 == i ? (n += int2char(e << 2 | v >> 4), e = 15 & v, i = 2) : 2 == i ? (n += int2char(e), n += int2char(v >> 2), e = 3 & v, i = 3) : (n += int2char(e << 2 | v >> 4), n += int2char(15 & v), i = 0));
    return 1 == i && (n += int2char(e << 2)), n
}

function b64toBA(t) {
    var r, e = b64tohex(t),
        n = new Array;
    for (r = 0; 2 * r < e.length; ++r) n[r] = parseInt(e.substring(2 * r, 2 * r + 2), 16);
    return n
}
var dbits, canary = 0xdeadbeefcafe,
    j_lm = 15715070 == (16777215 & canary);
j_lm && "Microsoft Internet Explorer" == navigator.appName ? (BigInteger.prototype.am = am2, dbits = 30) : j_lm && "Netscape" != navigator.appName ? (BigInteger.prototype.am = am1, dbits = 26) : (BigInteger.prototype.am = am3, dbits = 28), BigInteger.prototype.DB = dbits, BigInteger.prototype.DM = (1 << dbits) - 1, BigInteger.prototype.DV = 1 << dbits;
var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2, BI_FP), BigInteger.prototype.F1 = BI_FP - dbits, BigInteger.prototype.F2 = 2 * dbits - BI_FP;
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz",
    BI_RC = new Array,
    rr, vv;
for (rr = "0".charCodeAt(0), vv = 0; 9 >= vv; ++vv) BI_RC[rr++] = vv;
for (rr = "a".charCodeAt(0), vv = 10; 36 > vv; ++vv) BI_RC[rr++] = vv;
for (rr = "A".charCodeAt(0), vv = 10; 36 > vv; ++vv) BI_RC[rr++] = vv;
Classic.prototype.convert = cConvert, Classic.prototype.revert = cRevert, Classic.prototype.reduce = cReduce, Classic.prototype.mulTo = cMulTo, Classic.prototype.sqrTo = cSqrTo, Montgomery.prototype.convert = montConvert, Montgomery.prototype.revert = montRevert, Montgomery.prototype.reduce = montReduce, Montgomery.prototype.mulTo = montMulTo, Montgomery.prototype.sqrTo = montSqrTo, BigInteger.prototype.copyTo = bnpCopyTo, BigInteger.prototype.fromInt = bnpFromInt, BigInteger.prototype.fromString = bnpFromString, BigInteger.prototype.clamp = bnpClamp, BigInteger.prototype.dlShiftTo = bnpDLShiftTo, BigInteger.prototype.drShiftTo = bnpDRShiftTo, BigInteger.prototype.lShiftTo = bnpLShiftTo, BigInteger.prototype.rShiftTo = bnpRShiftTo, BigInteger.prototype.subTo = bnpSubTo, BigInteger.prototype.multiplyTo = bnpMultiplyTo, BigInteger.prototype.squareTo = bnpSquareTo, BigInteger.prototype.divRemTo = bnpDivRemTo, BigInteger.prototype.invDigit = bnpInvDigit, BigInteger.prototype.isEven = bnpIsEven, BigInteger.prototype.exp = bnpExp, BigInteger.prototype.toString = bnToString, BigInteger.prototype.negate = bnNegate, BigInteger.prototype.abs = bnAbs, BigInteger.prototype.compareTo = bnCompareTo, BigInteger.prototype.bitLength = bnBitLength, BigInteger.prototype.mod = bnMod, BigInteger.prototype.modPowInt = bnModPowInt, BigInteger.ZERO = nbv(0), BigInteger.ONE = nbv(1), Arcfour.prototype.init = ARC4init, Arcfour.prototype.next = ARC4next;
var rng_psize = 256,
    rng_state, rng_pool, rng_pptr;
if (null == rng_pool) {
    rng_pool = new Array, rng_pptr = 0;
    var t;
    if (window.crypto && window.crypto.getRandomValues) {
        var ua = new Uint8Array(32);
        for (window.crypto.getRandomValues(ua), t = 0; 32 > t; ++t) rng_pool[rng_pptr++] = ua[t]
    }
    if ("Netscape" == navigator.appName && navigator.appVersion < "5" && window.crypto) {
        var z = window.crypto.random(32);
        for (t = 0; t < z.length; ++t) rng_pool[rng_pptr++] = 255 & z.charCodeAt(t)
    }
    for (; rng_psize > rng_pptr;) t = Math.floor(65536 * Math.random()), rng_pool[rng_pptr++] = t >>> 8, rng_pool[rng_pptr++] = 255 & t;
    rng_pptr = 0, rng_seed_time()
}
SecureRandom.prototype.nextBytes = rng_get_bytes, RSAKey.prototype.doPublic = RSADoPublic, RSAKey.prototype.setPublic = RSASetPublic, RSAKey.prototype.encrypt = RSAEncrypt;
var b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    b64padchar = "=";
! function (t) {
    "use strict";

    function r(t, r) {
        return t.length > r && (t = t.substring(0, r) + o), t
    }

    function e(t, r) {
        t instanceof e ? (this.enc = t.enc, this.pos = t.pos) : (this.enc = t, this.pos = r)
    }

    function n(t, r, e, n, o) {
        if (!(n instanceof i)) throw "Invalid tag value.";
        this.stream = t, this.header = r, this.length = e, this.tag = n, this.sub = o
    }

    function i(t) {
        var r = t.get();
        if (this.tagClass = r >> 6, this.tagConstructed = 0 !== (32 & r), this.tagNumber = 31 & r, 31 == this.tagNumber) {
            var e = 0;
            this.tagNumber = 0;
            do {
                if (r = t.get(), e += 7, e > 53) throw "Tag numbers over 53 bits not supported at position " + (t.pos - 1);
                this.tagNumber = 128 * this.tagNumber + (127 & r)
            } while (128 & r)
        }
    }
    var o = "â€¦",
        s = /^((?:1[89]|2\d)?\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])(?:([0-5]\d)(?:([0-5]\d)(?:[.,](\d{1,3}))?)?)?(Z|[-+](?:[0]\d|1[0-2])([0-5]\d)?)?$/;
    e.prototype.get = function (r) {
        if (r === t && (r = this.pos++), r >= this.enc.length) throw "Requesting byte offset " + r + " on a stream of length " + this.enc.length;
        return this.enc[r]
    }, e.prototype.hexDigits = "0123456789ABCDEF", e.prototype.hexByte = function (t) {
        return this.hexDigits.charAt(t >> 4 & 15) + this.hexDigits.charAt(15 & t)
    }, e.prototype.hexDump = function (t, r, e) {
        for (var n = "", i = t; r > i; ++i)
            if (n += this.hexByte(this.get(i)), e !== !0) switch (15 & i) {
                case 7:
                    n += "  ";
                    break;
                case 15:
                    n += "\n";
                    break;
                default:
                    n += " "
            }
            return n
    }, e.prototype.isASCII = function (t, r) {
        for (var e = t; r > e; ++e) {
            var n = this.get(e);
            if (32 > n || n > 176) return !1
        }
        return !0
    }, e.prototype.parseStringISO = function (t, r) {
        for (var e = "", n = t; r > n; ++n) e += String.fromCharCode(this.get(n));
        return e
    }, e.prototype.parseStringUTF = function (t, r) {
        for (var e = "", n = t; r > n;) {
            var i = this.get(n++);
            e += String.fromCharCode(128 > i ? i : i > 191 && 224 > i ? (31 & i) << 6 | 63 & this.get(n++) : (15 & i) << 12 | (63 & this.get(n++)) << 6 | 63 & this.get(n++))
        }
        return e
    }, e.prototype.parseStringBMP = function (t, r) {
        for (var e, n, i = "", o = t; r > o;) e = this.get(o++), n = this.get(o++), i += String.fromCharCode(e << 8 | n);
        return i
    }, e.prototype.parseTime = function (t, r, e) {
        var n = this.parseStringISO(t, r),
            i = s.exec(n);
        return i ? (e && (i[1] = +i[1], i[1] += i[1] < 70 ? 2e3 : 1900), n = i[1] + "-" + i[2] + "-" + i[3] + " " + i[4], i[5] && (n += ":" + i[5], i[6] && (n += ":" + i[6], i[7] && (n += "." + i[7]))), i[8] && (n += " UTC", "Z" != i[8] && (n += i[8], i[9] && (n += ":" + i[9]))), n) : "Unrecognized time: " + n
    }, e.prototype.parseInteger = function (t, r) {
        var e = r - t;
        if (e > 6) {
            e <<= 3;
            var n = this.get(t);
            if (0 === n) e -= 8;
            else
                for (; 128 > n;) n <<= 1, --e;
            return "(" + e + " bit)"
        }
        for (var i = 0, o = t; r > o; ++o) i = 256 * i + this.get(o);
        return i
    }, e.prototype.parseBitString = function (t, e, n) {
        for (var i = this.get(t), o = (e - t - 1 << 3) - i, s = "(" + o + " bit)\n", a = "", h = i, u = e - 1; u > t; --u) {
            for (var c = this.get(u), f = h; 8 > f; ++f) a += c >> f & 1 ? "1" : "0";
            if (h = 0, a.length > n) return s + r(a, n)
        }
        return s + a
    }, e.prototype.parseOctetString = function (t, e, n) {
        if (this.isASCII(t, e)) return r(this.parseStringISO(t, e), n);
        var i = e - t,
            s = "(" + i + " byte)\n";
        n /= 2, i > n && (e = t + n);
        for (var a = t; e > a; ++a) s += this.hexByte(this.get(a));
        return i > n && (s += o), s
    }, e.prototype.parseOID = function (t, e, n) {
        for (var i = "", o = 0, s = 0, a = t; e > a; ++a) {
            var h = this.get(a);
            if (o = 128 * o + (127 & h), s += 7, !(128 & h)) {
                if ("" === i) {
                    var u = 80 > o ? 40 > o ? 0 : 1 : 2;
                    i = u + "." + (o - 40 * u)
                } else i += "." + (s > 53 ? "bigint" : o);
                if (o = s = 0, i.length > n) return r(i, n)
            }
        }
        return s > 0 && (i += ".incomplete"), i
    }, n.prototype.typeName = function () {
        switch (this.tag.tagClass) {
            case 0:
                switch (this.tag.tagNumber) {
                    case 0:
                        return "EOC";
                    case 1:
                        return "BOOLEAN";
                    case 2:
                        return "INTEGER";
                    case 3:
                        return "BIT_STRING";
                    case 4:
                        return "OCTET_STRING";
                    case 5:
                        return "NULL";
                    case 6:
                        return "OBJECT_IDENTIFIER";
                    case 7:
                        return "ObjectDescriptor";
                    case 8:
                        return "EXTERNAL";
                    case 9:
                        return "REAL";
                    case 10:
                        return "ENUMERATED";
                    case 11:
                        return "EMBEDDED_PDV";
                    case 12:
                        return "UTF8String";
                    case 16:
                        return "SEQUENCE";
                    case 17:
                        return "SET";
                    case 18:
                        return "NumericString";
                    case 19:
                        return "PrintableString";
                    case 20:
                        return "TeletexString";
                    case 21:
                        return "VideotexString";
                    case 22:
                        return "IA5String";
                    case 23:
                        return "UTCTime";
                    case 24:
                        return "GeneralizedTime";
                    case 25:
                        return "GraphicString";
                    case 26:
                        return "VisibleString";
                    case 27:
                        return "GeneralString";
                    case 28:
                        return "UniversalString";
                    case 30:
                        return "BMPString";
                    default:
                        return "Universal_" + this.tag.tagNumber.toString(16)
                }
            case 1:
                return "Application_" + this.tag.tagNumber.toString(16);
            case 2:
                return "[" + this.tag.tagNumber + "]";
            case 3:
                return "Private_" + this.tag.tagNumber.toString(16)
        }
    }, n.prototype.content = function (e) {
        if (this.tag === t) return null;
        e === t && (e = 1 / 0);
        var n = this.posContent(),
            i = Math.abs(this.length);
        if (!this.tag.isUniversal()) return null !== this.sub ? "(" + this.sub.length + " elem)" : this.stream.parseOctetString(n, n + i, e);
        switch (this.tag.tagNumber) {
            case 1:
                return 0 === this.stream.get(n) ? "false" : "true";
            case 2:
                return this.stream.parseInteger(n, n + i);
            case 3:
                return this.sub ? "(" + this.sub.length + " elem)" : this.stream.parseBitString(n, n + i, e);
            case 4:
                return this.sub ? "(" + this.sub.length + " elem)" : this.stream.parseOctetString(n, n + i, e);
            case 6:
                return this.stream.parseOID(n, n + i, e);
            case 16:
            case 17:
                return "(" + this.sub.length + " elem)";
            case 12:
                return r(this.stream.parseStringUTF(n, n + i), e);
            case 18:
            case 19:
            case 20:
            case 21:
            case 22:
            case 26:
                return r(this.stream.parseStringISO(n, n + i), e);
            case 30:
                return r(this.stream.parseStringBMP(n, n + i), e);
            case 23:
            case 24:
                return this.stream.parseTime(n, n + i, 23 == this.tag.tagNumber)
        }
        return null
    }, n.prototype.toString = function () {
        return this.typeName() + "@" + this.stream.pos + "[header:" + this.header + ",length:" + this.length + ",sub:" + (null === this.sub ? "null" : this.sub.length) + "]"
    }, n.prototype.toPrettyString = function (r) {
        r === t && (r = "");
        var e = r + this.typeName() + " @" + this.stream.pos;
        if (this.length >= 0 && (e += "+"), e += this.length, this.tag.tagConstructed ? e += " (constructed)" : !this.tag.isUniversal() || 3 != this.tag.tagNumber && 4 != this.tag.tagNumber || null === this.sub || (e += " (encapsulates)"), e += "\n", null !== this.sub) {
            r += "  ";
            for (var n = 0, i = this.sub.length; i > n; ++n) e += this.sub[n].toPrettyString(r)
        }
        return e
    }, n.prototype.posStart = function () {
        return this.stream.pos
    }, n.prototype.posContent = function () {
        return this.stream.pos + this.header
    }, n.prototype.posEnd = function () {
        return this.stream.pos + this.header + Math.abs(this.length)
    }, n.prototype.toHexString = function () {
        return this.stream.hexDump(this.posStart(), this.posEnd(), !0)
    }, n.decodeLength = function (t) {
        var r = t.get(),
            e = 127 & r;
        if (e == r) return e;
        if (e > 6) throw "Length over 48 bits not supported at position " + (t.pos - 1);
        if (0 === e) return null;
        r = 0;
        for (var n = 0; e > n; ++n) r = 256 * r + t.get();
        return r
    }, i.prototype.isUniversal = function () {
        return 0 === this.tagClass
    }, i.prototype.isEOC = function () {
        return 0 === this.tagClass && 0 === this.tagNumber
    }, n.decode = function (t) {
        t instanceof e || (t = new e(t, 0));
        var r = new e(t),
            o = new i(t),
            s = n.decodeLength(t),
            a = t.pos,
            h = a - r.pos,
            u = null,
            c = function () {
                if (u = [], null !== s) {
                    for (var r = a + s; t.pos < r;) u[u.length] = n.decode(t);
                    if (t.pos != r) throw "Content size is not correct for container starting at offset " + a
                } else try {
                    for (;;) {
                        var e = n.decode(t);
                        if (e.tag.isEOC()) break;
                        u[u.length] = e
                    }
                    s = a - t.pos
                } catch (i) {
                    throw "Exception while decoding undefined length content: " + i
                }
            };
        if (o.tagConstructed) c();
        else if (o.isUniversal() && (3 == o.tagNumber || 4 == o.tagNumber)) {
            o.isUniversal() && 3 == o.tagNumber && t.get();
            try {
                c();
                for (var f = 0; f < u.length; ++f)
                    if (u[f].tag.isEOC()) throw "EOC is not supposed to be actual content."
            } catch (p) {
                u = null
            }
        }
        if (null === u) {
            if (null === s) throw "We can't skip over an invalid tag with undefined length at offset " + a;
            t.pos = a + Math.abs(s)
        }
        return new n(r, h, s, o, u)
    }, "undefined" != typeof module ? module.exports = n : window.ASN1 = n
}(),
function (t, r) {
    "object" == typeof exports ? module.exports = r() : "function" == typeof define && define.amd ? define(r) : t.GibberishAES = r()
}(this, function () {
    "use strict";
    var t = 14,
        r = 8,
        e = !1,
        n = function (t) {
            try {
                return unescape(encodeURIComponent(t))
            } catch (r) {
                throw "Error on UTF-8 encode"
            }
        },
        i = function (t) {
            try {
                return decodeURIComponent(escape(t))
            } catch (r) {
                throw "Bad Key"
            }
        },
        o = function (t) {
            var r, e, n = [];
            for (t.length < 16 && (r = 16 - t.length, n = [r, r, r, r, r, r, r, r, r, r, r, r, r, r, r, r]), e = 0; e < t.length; e++) n[e] = t[e];
            return n
        },
        s = function (t, r) {
            var e, n, i = "";
            if (r) {
                if (e = t[15], e > 16) throw "Decryption error: Maybe bad key";
                if (16 === e) return "";
                for (n = 0; 16 - e > n; n++) i += String.fromCharCode(t[n])
            } else
                for (n = 0; 16 > n; n++) i += String.fromCharCode(t[n]);
            return i
        },
        a = function (t) {
            var r, e = "";
            for (r = 0; r < t.length; r++) e += (t[r] < 16 ? "0" : "") + t[r].toString(16);
            return e
        },
        h = function (t) {
            var r = [];
            return t.replace(/(..)/g, function (t) {
                r.push(parseInt(t, 16))
            }), r
        },
        u = function (t, r) {
            var e, i = [];
            for (r || (t = n(t)), e = 0; e < t.length; e++) i[e] = t.charCodeAt(e);
            return i
        },
        c = function (e) {
            switch (e) {
                case 128:
                    t = 10, r = 4;
                    break;
                case 192:
                    t = 12, r = 6;
                    break;
                case 256:
                    t = 14, r = 8;
                    break;
                default:
                    throw "Invalid Key Size Specified:" + e
            }
        },
        f = function (t) {
            var r, e = [];
            for (r = 0; t > r; r++) e = e.concat(Math.floor(256 * Math.random()));
            return e
        },
        p = function (e, n) {
            var i, o = t >= 12 ? 3 : 2,
                s = [],
                a = [],
                h = [],
                u = [],
                c = e.concat(n);
            for (h[0] = U(c), u = h[0], i = 1; o > i; i++) h[i] = U(h[i - 1].concat(c)), u = u.concat(h[i]);
            return s = u.slice(0, 4 * r), a = u.slice(4 * r, 4 * r + 16), {
                key: s,
                iv: a
            }
        },
        g = function (t, r, e) {
            r = T(r);
            var n, i = Math.ceil(t.length / 16),
                s = [],
                a = [];
            for (n = 0; i > n; n++) s[n] = o(t.slice(16 * n, 16 * n + 16));
            for (t.length % 16 === 0 && (s.push([16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]), i++), n = 0; n < s.length; n++) s[n] = 0 === n ? I(s[n], e) : I(s[n], a[n - 1]), a[n] = d(s[n], r);
            return a
        },
        l = function (t, r, e, n) {
            r = T(r);
            var o, a = t.length / 16,
                h = [],
                u = [],
                c = "";
            for (o = 0; a > o; o++) h.push(t.slice(16 * o, 16 * (o + 1)));
            for (o = h.length - 1; o >= 0; o--) u[o] = b(h[o], r), u[o] = 0 === o ? I(u[o], e) : I(u[o], h[o - 1]);
            for (o = 0; a - 1 > o; o++) c += s(u[o]);
            return c += s(u[o], !0), n ? c : i(c)
        },
        d = function (r, n) {
            e = !1;
            var i, o = S(r, n, 0);
            for (i = 1; t + 1 > i; i++) o = v(o), o = m(o), t > i && (o = y(o)), o = S(o, n, i);
            return o
        },
        b = function (r, n) {
            e = !0;
            var i, o = S(r, n, t);
            for (i = t - 1; i > -1; i--) o = m(o), o = v(o), o = S(o, n, i), i > 0 && (o = y(o));
            return o
        },
        v = function (t) {
            var r, n = e ? M : E,
                i = [];
            for (r = 0; 16 > r; r++) i[r] = n[t[r]];
            return i
        },
        m = function (t) {
            var r, n = [],
                i = e ? [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3] : [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];
            for (r = 0; 16 > r; r++) n[r] = t[i[r]];
            return n
        },
        y = function (t) {
            var r, n = [];
            if (e)
                for (r = 0; 4 > r; r++) n[4 * r] = P[t[4 * r]] ^ F[t[1 + 4 * r]] ^ k[t[2 + 4 * r]] ^ O[t[3 + 4 * r]], n[1 + 4 * r] = O[t[4 * r]] ^ P[t[1 + 4 * r]] ^ F[t[2 + 4 * r]] ^ k[t[3 + 4 * r]], n[2 + 4 * r] = k[t[4 * r]] ^ O[t[1 + 4 * r]] ^ P[t[2 + 4 * r]] ^ F[t[3 + 4 * r]], n[3 + 4 * r] = F[t[4 * r]] ^ k[t[1 + 4 * r]] ^ O[t[2 + 4 * r]] ^ P[t[3 + 4 * r]];
            else
                for (r = 0; 4 > r; r++) n[4 * r] = x[t[4 * r]] ^ N[t[1 + 4 * r]] ^ t[2 + 4 * r] ^ t[3 + 4 * r], n[1 + 4 * r] = t[4 * r] ^ x[t[1 + 4 * r]] ^ N[t[2 + 4 * r]] ^ t[3 + 4 * r], n[2 + 4 * r] = t[4 * r] ^ t[1 + 4 * r] ^ x[t[2 + 4 * r]] ^ N[t[3 + 4 * r]], n[3 + 4 * r] = N[t[4 * r]] ^ t[1 + 4 * r] ^ t[2 + 4 * r] ^ x[t[3 + 4 * r]];
            return n
        },
        S = function (t, r, e) {
            var n, i = [];
            for (n = 0; 16 > n; n++) i[n] = t[n] ^ r[e][n];
            return i
        },
        I = function (t, r) {
            var e, n = [];
            for (e = 0; 16 > e; e++) n[e] = t[e] ^ r[e];
            return n
        },
        T = function (e) {
            var n, i, o, s, a = [],
                h = [],
                u = [];
            for (n = 0; r > n; n++) i = [e[4 * n], e[4 * n + 1], e[4 * n + 2], e[4 * n + 3]], a[n] = i;
            for (n = r; 4 * (t + 1) > n; n++) {
                for (a[n] = [], o = 0; 4 > o; o++) h[o] = a[n - 1][o];
                for (n % r === 0 ? (h = B(A(h)), h[0] ^= R[n / r - 1]) : r > 6 && n % r === 4 && (h = B(h)), o = 0; 4 > o; o++) a[n][o] = a[n - r][o] ^ h[o]
            }
            for (n = 0; t + 1 > n; n++)
                for (u[n] = [], s = 0; 4 > s; s++) u[n].push(a[4 * n + s][0], a[4 * n + s][1], a[4 * n + s][2], a[4 * n + s][3]);
            return u
        },
        B = function (t) {
            for (var r = 0; 4 > r; r++) t[r] = E[t[r]];
            return t
        },
        A = function (t) {
            var r, e = t[0];
            for (r = 0; 4 > r; r++) t[r] = t[r + 1];
            return t[3] = e, t
        },
        D = function (t, r) {
            var e, n = [];
            for (e = 0; e < t.length; e += r) n[e / r] = parseInt(t.substr(e, r), 16);
            return n
        },
        _ = function (t) {
            var r, e = [];
            for (r = 0; r < t.length; r++) e[t[r]] = r;
            return e
        },
        C = function (t, r) {
            var e, n;
            for (n = 0, e = 0; 8 > e; e++) n = 1 === (1 & r) ? n ^ t : n, t = t > 127 ? 283 ^ t << 1 : t << 1, r >>>= 1;
            return n
        },
        w = function (t) {
            var r, e = [];
            for (r = 0; 256 > r; r++) e[r] = C(t, r);
            return e
        },
        E = D("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16", 2),
        M = _(E),
        R = D("01020408102040801b366cd8ab4d9a2f5ebc63c697356ad4b37dfaefc591", 2),
        x = w(2),
        N = w(3),
        O = w(9),
        F = w(11),
        k = w(13),
        P = w(14),
        q = function (t, r, e) {
            var n, i = f(8),
                o = p(u(r, e), i),
                s = o.key,
                a = o.iv,
                h = [
                    [83, 97, 108, 116, 101, 100, 95, 95].concat(i)
                ];
            return t = u(t, e), n = g(t, s, a), n = h.concat(n), j.encode(n)
        },
        L = function (t, r, e) {
            var n = j.decode(t),
                i = n.slice(8, 16),
                o = p(u(r, e), i),
                s = o.key,
                a = o.iv;
            return n = n.slice(16, n.length), t = l(n, s, a, e)
        },
        U = function (t) {
            function r(t, r) {
                return t << r | t >>> 32 - r
            }

            function e(t, r) {
                var e, n, i, o, s;
                return i = 2147483648 & t, o = 2147483648 & r, e = 1073741824 & t, n = 1073741824 & r, s = (1073741823 & t) + (1073741823 & r), e & n ? 2147483648 ^ s ^ i ^ o : e | n ? 1073741824 & s ? 3221225472 ^ s ^ i ^ o : 1073741824 ^ s ^ i ^ o : s ^ i ^ o
            }

            function n(t, r, e) {
                return t & r | ~t & e
            }

            function i(t, r, e) {
                return t & e | r & ~e
            }

            function o(t, r, e) {
                return t ^ r ^ e
            }

            function s(t, r, e) {
                return r ^ (t | ~e)
            }

            function a(t, i, o, s, a, h, u) {
                return t = e(t, e(e(n(i, o, s), a), u)), e(r(t, h), i)
            }

            function h(t, n, o, s, a, h, u) {
                return t = e(t, e(e(i(n, o, s), a), u)), e(r(t, h), n)
            }

            function u(t, n, i, s, a, h, u) {
                return t = e(t, e(e(o(n, i, s), a), u)), e(r(t, h), n)
            }

            function c(t, n, i, o, a, h, u) {
                return t = e(t, e(e(s(n, i, o), a), u)), e(r(t, h), n)
            }

            function f(t) {
                for (var r, e = t.length, n = e + 8, i = (n - n % 64) / 64, o = 16 * (i + 1), s = [], a = 0, h = 0; e > h;) r = (h - h % 4) / 4, a = h % 4 * 8, s[r] = s[r] | t[h] << a, h++;
                return r = (h - h % 4) / 4, a = h % 4 * 8, s[r] = s[r] | 128 << a, s[o - 2] = e << 3, s[o - 1] = e >>> 29, s
            }

            function p(t) {
                var r, e, n = [];
                for (e = 0; 3 >= e; e++) r = t >>> 8 * e & 255, n = n.concat(r);
                return n
            }
            var g, l, d, b, v, m, y, S, I, T = [],
                B = D("67452301efcdab8998badcfe10325476d76aa478e8c7b756242070dbc1bdceeef57c0faf4787c62aa8304613fd469501698098d88b44f7afffff5bb1895cd7be6b901122fd987193a679438e49b40821f61e2562c040b340265e5a51e9b6c7aad62f105d02441453d8a1e681e7d3fbc821e1cde6c33707d6f4d50d87455a14eda9e3e905fcefa3f8676f02d98d2a4c8afffa39428771f6816d9d6122fde5380ca4beea444bdecfa9f6bb4b60bebfbc70289b7ec6eaa127fad4ef308504881d05d9d4d039e6db99e51fa27cf8c4ac5665f4292244432aff97ab9423a7fc93a039655b59c38f0ccc92ffeff47d85845dd16fa87e4ffe2ce6e0a30143144e0811a1f7537e82bd3af2352ad7d2bbeb86d391", 8);
            for (T = f(t), m = B[0], y = B[1], S = B[2], I = B[3], g = 0; g < T.length; g += 16) l = m, d = y, b = S, v = I, m = a(m, y, S, I, T[g + 0], 7, B[4]), I = a(I, m, y, S, T[g + 1], 12, B[5]), S = a(S, I, m, y, T[g + 2], 17, B[6]), y = a(y, S, I, m, T[g + 3], 22, B[7]), m = a(m, y, S, I, T[g + 4], 7, B[8]), I = a(I, m, y, S, T[g + 5], 12, B[9]), S = a(S, I, m, y, T[g + 6], 17, B[10]), y = a(y, S, I, m, T[g + 7], 22, B[11]), m = a(m, y, S, I, T[g + 8], 7, B[12]), I = a(I, m, y, S, T[g + 9], 12, B[13]), S = a(S, I, m, y, T[g + 10], 17, B[14]), y = a(y, S, I, m, T[g + 11], 22, B[15]), m = a(m, y, S, I, T[g + 12], 7, B[16]), I = a(I, m, y, S, T[g + 13], 12, B[17]), S = a(S, I, m, y, T[g + 14], 17, B[18]), y = a(y, S, I, m, T[g + 15], 22, B[19]), m = h(m, y, S, I, T[g + 1], 5, B[20]), I = h(I, m, y, S, T[g + 6], 9, B[21]), S = h(S, I, m, y, T[g + 11], 14, B[22]), y = h(y, S, I, m, T[g + 0], 20, B[23]), m = h(m, y, S, I, T[g + 5], 5, B[24]), I = h(I, m, y, S, T[g + 10], 9, B[25]), S = h(S, I, m, y, T[g + 15], 14, B[26]), y = h(y, S, I, m, T[g + 4], 20, B[27]), m = h(m, y, S, I, T[g + 9], 5, B[28]), I = h(I, m, y, S, T[g + 14], 9, B[29]), S = h(S, I, m, y, T[g + 3], 14, B[30]), y = h(y, S, I, m, T[g + 8], 20, B[31]), m = h(m, y, S, I, T[g + 13], 5, B[32]), I = h(I, m, y, S, T[g + 2], 9, B[33]), S = h(S, I, m, y, T[g + 7], 14, B[34]), y = h(y, S, I, m, T[g + 12], 20, B[35]), m = u(m, y, S, I, T[g + 5], 4, B[36]), I = u(I, m, y, S, T[g + 8], 11, B[37]), S = u(S, I, m, y, T[g + 11], 16, B[38]), y = u(y, S, I, m, T[g + 14], 23, B[39]), m = u(m, y, S, I, T[g + 1], 4, B[40]), I = u(I, m, y, S, T[g + 4], 11, B[41]), S = u(S, I, m, y, T[g + 7], 16, B[42]), y = u(y, S, I, m, T[g + 10], 23, B[43]), m = u(m, y, S, I, T[g + 13], 4, B[44]), I = u(I, m, y, S, T[g + 0], 11, B[45]), S = u(S, I, m, y, T[g + 3], 16, B[46]), y = u(y, S, I, m, T[g + 6], 23, B[47]), m = u(m, y, S, I, T[g + 9], 4, B[48]), I = u(I, m, y, S, T[g + 12], 11, B[49]), S = u(S, I, m, y, T[g + 15], 16, B[50]), y = u(y, S, I, m, T[g + 2], 23, B[51]), m = c(m, y, S, I, T[g + 0], 6, B[52]), I = c(I, m, y, S, T[g + 7], 10, B[53]), S = c(S, I, m, y, T[g + 14], 15, B[54]), y = c(y, S, I, m, T[g + 5], 21, B[55]), m = c(m, y, S, I, T[g + 12], 6, B[56]), I = c(I, m, y, S, T[g + 3], 10, B[57]), S = c(S, I, m, y, T[g + 10], 15, B[58]), y = c(y, S, I, m, T[g + 1], 21, B[59]), m = c(m, y, S, I, T[g + 8], 6, B[60]), I = c(I, m, y, S, T[g + 15], 10, B[61]), S = c(S, I, m, y, T[g + 6], 15, B[62]), y = c(y, S, I, m, T[g + 13], 21, B[63]), m = c(m, y, S, I, T[g + 4], 6, B[64]), I = c(I, m, y, S, T[g + 11], 10, B[65]), S = c(S, I, m, y, T[g + 2], 15, B[66]), y = c(y, S, I, m, T[g + 9], 21, B[67]), m = e(m, l), y = e(y, d), S = e(S, b), I = e(I, v);
            return p(m).concat(p(y), p(S), p(I))
        },
        j = function () {
            var t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                r = t.split(""),
                e = function (t) {
                    {
                        var e, n, i = [],
                            o = "";
                        Math.floor(16 * t.length / 3)
                    }
                    for (e = 0; e < 16 * t.length; e++) i.push(t[Math.floor(e / 16)][e % 16]);
                    for (e = 0; e < i.length; e += 3) o += r[i[e] >> 2], o += r[(3 & i[e]) << 4 | i[e + 1] >> 4], o += void 0 !== i[e + 1] ? r[(15 & i[e + 1]) << 2 | i[e + 2] >> 6] : "=", o += void 0 !== i[e + 2] ? r[63 & i[e + 2]] : "=";
                    for (n = o.slice(0, 64) + "\n", e = 1; e < Math.ceil(o.length / 64); e++) n += o.slice(64 * e, 64 * e + 64) + (Math.ceil(o.length / 64) === e + 1 ? "" : "\n");
                    return n
                },
                n = function (r) {
                    r = r.replace(/\n/g, "");
                    var e, n = [],
                        i = [],
                        o = [];
                    for (e = 0; e < r.length; e += 4) i[0] = t.indexOf(r.charAt(e)), i[1] = t.indexOf(r.charAt(e + 1)), i[2] = t.indexOf(r.charAt(e + 2)), i[3] = t.indexOf(r.charAt(e + 3)), o[0] = i[0] << 2 | i[1] >> 4, o[1] = (15 & i[1]) << 4 | i[2] >> 2, o[2] = (3 & i[2]) << 6 | i[3], n.push(o[0], o[1], o[2]);
                    return n = n.slice(0, n.length - n.length % 16)
                };
            return "function" == typeof Array.indexOf && (t = r), {
                encode: e,
                decode: n
            }
        }();
    return {
        size: c,
        h2a: h,
        expandKey: T,
        encryptBlock: d,
        decryptBlock: b,
        Decrypt: e,
        s2a: u,
        rawEncrypt: g,
        rawDecrypt: l,
        dec: L,
        openSSLKey: p,
        a2h: a,
        enc: q,
        Hash: {
            MD5: U
        },
        Base64: j
    }
});
var My2c2p = {
    version: "1.0"
};
My2c2p.errorDescription = function (t) {
    var r = ["card number is required", "card number is invalid", "expiry month is required", "expiry month must be two characters", "expiry year is required", "expiry year must be four characters", "card already expired(year)", "card already expired(month)", "invalid card expiry month", "invalid cvv", "invalid month", "invalid year"];
    return t - 1 > r.length ? "unknown error" : r[t - 1]
};
var extractForm = function (t) {
    return window.jQuery && t instanceof jQuery ? t[0] : t.nodeType && 1 === t.nodeType ? t : document.getElementById(t)
};
My2c2p.onSubmitForm = function (t, r, cardObject) {
    var e = this,
        n = window._2c2pKey,
        o = function (t) {
            var r = [],
                e = 0;
            for (e = 0; e < t.children.length; e++) child = t.children[e], 1 === child.nodeType && child.attributes["data-encrypt"] ? r.push(child) : child.children.length > 0 && (r = r.concat(o(child)));
            return r
        },
        s = function (t) {
            if (cardObject) return cardObject;
            for (var r = {
                    cardnumber: "",
                    cvv: "",
                    month: "",
                    year: ""
                }, e = o(t), n = 0; n < e.length; n++) {
                var i = e[n].value;
                e[n].removeAttribute("name");
                var s = e[n].attributes["data-encrypt"].value;
                "cardnumber" == s ? r.cardnumber = i : "cvv" == s ? r.cvv = i : "month" == s ? r.month = i : "year" == s && (r.year = i)
            }
            return r
        },
        a = function () {
            for (var t = "", r = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-+=_", e = 0; 8 > e; e++) t += r.charAt(Math.floor(Math.random() * r.length));
            return t
        },
        u = function (t, r) {
            return GibberishAES.enc(t, r)
        },
        c = function (t) {
            var r, e, n, i, o = [];
            if ("INTEGER" === t.typeName() && (r = t.posContent(), e = t.posEnd(), n = t.stream.hexDump(r, e), n = n.replace(/[ \n]/g, ""), o.push(n)), null !== t.sub)
                for (i = 0; i < t.sub.length; i++) {
                    var s = c(t.sub[i]);
                    o = o.concat(s)
                }
            return o
        },
        f = function (t) {
            var r, e, i = n;
            try {
                r = b64toBA(i), e = ASN1.decode(r)
            } catch (o) {
                throw "Invalid public key."
            }
            var s = c(e);
            if (2 != s.length) throw "Invalid public key.";
            var a = s[0],
                h = s[1];
            "00" == a.substr(0, 2) && (a = a.substr(2)), "0" == h.substr(0, 1) && (h = h.substr(1));
            var u = new RSAKey;
            u.setPublic(a, h);
            var f = u.encrypt(t);
            return hex2b64(f)
        },
        p = function (t, r, e) {
            var n = document.createElement("input");
            n.setAttribute("type", "hidden"), n.setAttribute("name", r), n.setAttribute("value", e), t.appendChild(n)
        };
    e.isEmpty = function (t) {
        return !t || 0 === t.length
    };
    var g = function (t) {
            var r, e, n, i, o;
            for (i = "", r = 0; r < t.length; r++) n = parseInt(t.charAt(r), 10), n >= 0 && 9 >= n && (i = n + i);
            if (i.length <= 1) return !1;
            for (o = "", r = 0; r < i.length; r++) n = parseInt(i.charAt(r), 10), r % 2 != 0 && (n *= 2), o += n;
            for (e = 0, r = 0; r < o.length; r++) n = parseInt(o.charAt(r), 10), e += n;
            return 0 != e && e % 10 == 0 ? !0 : !1
        },
        l = function (t) {
            var r = new Date,
                n = r.getFullYear(),
                i = r.getMonth();
            i += 1;
            var o = s(t),
                a = parseInt(o.month, 10) || 0,
                h = parseInt(o.year, 10) || 0,
                u = !1;
            if (e.isEmpty(o.cardnumber) && e.isEmpty(o.month) && e.isEmpty(o.year) || (u = !0), u) {
                if (e.isEmpty(o.cardnumber)) return 1;
                if (e.isEmpty(o.month)) return 3;
                if (e.isEmpty(o.year)) return 5;
                if (!g(o.cardnumber)) return 2;
                if (o.month.length > 2 || o.month.length < 1) return 4;
                if (e.isEmpty(o.year)) return 5;
                if (4 != o.year.length) return 6;
                if (!o.month.match(/^\d+$/)) return 11;
                if (!o.year.match(/^\d+$/)) return 12;
                if (n > h) return 7;
                if (h == n) {
                    if (1 > a || a > 12) return 9;
                    if (i > a) return 8
                } else if (1 > a || a > 12) return 9;
                if (!o.cvv.match(/^[0-9]{3,4}$/)) return 10
            } else {
                if (e.isEmpty(o.cvv)) return 10;
                if (!o.cvv.match(/^[0-9]{3,4}$/) && !e.isEmpty(o.cvv)) return 10
            }
            return 0
        },
        d = function (t) {
            var r = t.substring(0, 6),
                e = t.substring(t.length - 4),
                n = t.length - 10,
                o = r;
            if (n > 0) {
                for (i = 0; n > i; i++) o += "X";
                return o += e
            }
            return t
        },
        b = function (t, returnToken) {
            var r = cardObject ? cardObject : s(t),
                e = a(),
                n = f(e),
                i = r.cardnumber,
                o = d(i),
                c = r.month,
                g = r.year,
                l = r.cvv,
                b = "",
                v = parseInt(r.month, 10) || 0;
            b = 10 > v ? "0" + v : "" + v;
            var m = r.year,
                y = i + ";" + b + ";" + m + ";" + l,
                S = u(y, e);
            y = "", i = "", l = "", b = "", m = "", e = "";
            var I = n.length,
                T = I.toString(16);
            for (h = T.length; 4 > h; h++) T = "0" + T;
            var B = T + n + S;
            if (returnToken) return B;
            B = B.replace("\n", ""), p(t, "encryptedCardInfo", B), p(t, "maskedCardInfo", o), p(t, "expMonthCardInfo", c), p(t, "expYearCardInfo", g)
        };
        if (!cardObject) {
            t = extractForm(t);
            e.callbackForm = function (n) {
                var i = l(t);
                0 != i ? ("" != n && n.preventDefault(), r ? r(i, e.errorDescription(i)) : alert(e.errorDescription(i))) : (b(t), r && r(0, ""))
            }, window.jQuery ? window.jQuery(t).submit(e.callbackForm) : t.addEventListener ? t.addEventListener("submit", e.callbackForm, !1) : t.attachEvent && t.attachEvent("onsubmit", e.callbackForm)
        } else {
            t = cardObject;
            var i = l(t);
            if (i) {
                alert(i);
                // "" != n && n.preventDefault();
                r ? r(i, e.errorDescription(i)) : alert(e.errorDescription(i))
            } else {
                window.cardToken = b(t, true);
                r && r(0, "");
            }
        }
},

My2c2p.submitForm = function (form, success, error, cardObject) {
    My2c2p.onSubmitForm(form, function (errorCode, errorMessage) {
        if (0 == errorCode && "" == errorMessage) {
            success(window.cardToken);
        } else {
            error(errorCode, errorMessage)
        }
    }, cardObject);
    !cardObject && My2c2p.callbackForm("");
};