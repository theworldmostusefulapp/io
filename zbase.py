#!/usr/bin/python3
# -*- coding: utf-8 -*-

import hashlib, base64, base65536

PAD = lambda s:(len(s)%2)*'0'+s[2:]

def i2b(x, n=1):
    z = bytes.fromhex(PAD(hex(x)))
    return ((n-len(z))%n)*bytes.fromhex('00') + z

def b2i(x):
    return int.from_bytes(x, 'big')

Z56C  = '23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz'
Z58C  = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
Z85C  = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#'
Z256C = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz¢£¥¦§¨ÎÏÐÑÒÓêëìíîïðûüýþÿĀāĂăĄąĆćĈĉĊċČčĎďĐđĒēĔĕġĢģĤĥĦħĨĩĪīĬĭĮįİıĲĳĴĵĶķĸĹĺĻļĽľĿŀŁōŎŏŐőŒœŔŕŖŗŘřŚśŝşŠšŢţŤťŦŧũźżžſƇƈƉƊƋƌƍƎƏƐƑƒƓƔƕƖƗƘƙƚƛƜƝƞƟƠơƢƣƤƥɣɤɥɦɧɨɩɪʒʓʔʕʖʗʘʙʚΥΦΧΨΩΪΫάέήίΰαβωϊϋόύώϏϐϑϒϓϔϕ϶ϷϸϹϺϻϼϽϾϿ'

Z56M  = {c:i for i, c in enumerate(Z56C)}
Z58M  = {c:i for i, c in enumerate(Z58C)}
Z85M  = {c:i for i, c in enumerate(Z85C)}
Z256M = {c:i for i, c in enumerate(Z256C)}
assert len(Z56C)  == len(Z56M)  == 56
assert len(Z58C)  == len(Z58M)  == 58
assert len(Z85C)  == len(Z85M)  == 85
assert len(Z256C) == len(Z256M) == 256

def z56encode(n):
    h = hashlib.sha1(n.to_bytes(8,'big')).digest()   
    o, n = '', (b2i(h[-1:])>>3) + (n<<5)
    if n==0: return Z56C[0]
    while n>0: o, n = Z56C[n%56] + o, n//56
    return o

def z58encode(n):
    h = hashlib.sha1(n.to_bytes(8,'big')).digest()
    o, n = '', (b2i(h[-1:])>>2) + (n<<6)
    if n==0: return Z58C[0]
    while n>0: o, n = Z58C[n%58] + o, n//58
    return o

def z85encode(n):
    o = ''
    if n==0: return Z85C[0]
    while n>0: o, n = Z85C[n%85] + o, n//85
    return o

def z256encode(n):
    h = hashlib.sha1(n.to_bytes(8,'big')).digest()
    o, n = '', (b2i(h[-1:])) + (n<<8)
    if n==0: return Z256C[0]
    while n>0: o, n = Z256C[n%256] + o, n//256
    return o

def z56check(x):
    w = sum(Z56M[i]*(56**(len(x)-1-p)) for p,i in enumerate(x)) 
    h = hashlib.sha1((w>>5).to_bytes(8,'big')).digest()
    return w&0x1F == b2i(h[-1:])>>3

def z58check(x):
    w = sum(Z58M[i]*(58**(len(x)-1-p)) for p,i in enumerate(x)) 
    h = hashlib.sha1((w>>6).to_bytes(8,'big')).digest()
    return w&0x3F == b2i(h[-1:])>>2

def z256check(x):
    w = sum(Z256M[i]*(58**(len(x)-1-p)) for p,i in enumerate(x)) 
    h = hashlib.sha1((w>>8).to_bytes(8,'big')).digest()
    return w&0xFF == b2i(h[-1:])

def z56decode(x):
    return sum(Z56M[i]*(56**(len(x)-1-p)) for p,i in enumerate(x)) >> 5
def z58decode(x):
    return sum(Z58M[i]*(58**(len(x)-1-p)) for p,i in enumerate(x)) >> 6
def z85decode(x):
    return sum(Z85M[i]*(85**(len(x)-1-p)) for p,i in enumerate(x))
def z256decode(x):
    return sum(Z256M[i]*(256**(len(x)-1-p)) for p,i in enumerate(x)) >> 8

if __name__ == "__main__":
    print (hex(256**8-1))
    # BASE56 12 CHARS WITH CS ON 5 BITS
    print (hex(((56**12)-1)>>5))
    print (hex(((56**12)-1)>>6))
    # BASE58 12 CHARS with CS ON 6 BITS
    print (hex(((58**12)-1)>>6))
    print (hex(((58**12)-1)>>7))
    # BASE85 10 CHARS WITHOUT CS
    print (hex((85**10-1)>>0))
    print (hex((85**10-1)>>1))
    
    for x in (0x00, 0x01, 0x456723AE62FEBC12, 0xFF6723AE62FEBCFE):
        assert x == z56decode(z56encode(x))   and z56check(z56encode(x))
        assert x == z58decode(z58encode(x))   and z58check(z58encode(x))
        assert x == z85decode(z85encode(x))   and True
        assert x == z256decode(z256encode(x)) and z58check(z58encode(x))
        print ('%016x' % x, z56encode(x), z85encode(x), z256encode(x), base65536.encode(i2b(x,8)))
        
    #print (''.join(chr(i) for i in range(33,1024)))
