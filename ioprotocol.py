#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
IO-PROTOCOL over UDP (client and server) v0.1

1/ IO DB FORMAT

DBHEAD: 01:016 IO_VER(1)       : TOTAL_NC(8)  WEALTH(8)      
S_HEAD: 08:012 SRC(8)          : LST_N_SRC(4) BAL_SRC(4) DEADLINE_SRC(4)
D_HEAD: 08:012 DST(8)          : LST_N_DST(4) BAL_DST(4) DEADLINE_DST(4)

PUBKEY: 11:050 ' '+ID(10)      : PUBLIC_KEY_END(50)[base85]
PUBKEY: 13:062 ' '+ID(10)      : PUBLIC_KEY_END(50)[base56]

TRANSATION 
TR_SRC: 12:026 SRC(8) N_SRC(4) : DST(8) N_DST(4)                                   BAL(4) H(10)
TR_DST: 12:142 DST(8) N_DST(4) : SRC(8)   DAT(4) LATLONG(8) MNT(4)  REF(8) SIG(96) BAL(4) H(10)
CERTIF: 12:148 SRC(8) N_SRC(4) : DST(8)   DAT(4) LATLONG(8) PLD(10) REF(8) SIG(96) BAL(4) H(10)

INVOIC: 12:148? SRC(8) N_SRC(4) : DST(8) DAT(4) LATLONG(8) HIST(16)  H(10) SIG(96)
        12:256                                            HIST(130)              

2/ API 
REGISTER    pk->48
CERTIFICATE msg(38)+sig(96)->134
TRANSACTION msg(32)+sig(96)->128

3/ TODO LIST
"""
import sys, os, socket, ecc, dbm, re, hashlib, leaf
#import tensorflow

s, k, MAXB, PORT = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), ecc.ecdsa(), 1000, 7800
NS, ND, NC = 26, 142, 148

def check(d):
    """

    """ 
    if len(d.keys()) > 0 and ecc.v1 not in d:         return  1 # head does not exists 
    wc, wr = 0, 0
    tc, tr = 0, 0
    for x in d.keys():
        # length
        l = len(d[x])
        if len(x) == 1  and l != 16:                  return  2 # bad length head
        if len(x) == 8  and l != 12:                  return  3 # bad length id head
        if len(x) == 11 and l != 50:                  return  4 # bad length pub key
        if len(x) == 13 and l != 60:                  return  4 # bad length pub key
        if len(x) == 12 and l not in (NS, ND, NC):    return  5 # bad length operation
        # Dates
        if len(x) == 8:
            dat = ecc.z8
            for i in range(ecc.b2i(d[x][:4])):
                dx = x + ecc.i2b(i+1, 4)
                if len(d[dx]) in (ND, NC):
                    if    d[dx][8:12] < dat:          return  6 # bad date increase
                    dat = d[dx][8:12]
                if len(d[dx]) == ND:
                    if dat > d[x][8:12]:              return  7 # invalid date/dead line

        # Public keys
        if len(x) == 12:
            if b' '+ecc.z56encode(x[:8]) not in d:    return  8 # src id unknown
            if b' '+ecc.z56encode(d[x][:8]) not in d: return  9 # dst id unknown 
        
        # Signatures
        if len(x) == 8:
            for i in range(ecc.b2i(d[x][:4])):
                dx = x + ecc.i2b(i+1, 4)
                if len(d[dx]) in (ND, NC):
                    zx = ecc.z56encode(d[dx][:8])                    
                    msg, sig = d[dx][:8] + dx[:8] + d[dx][8:-110], d[dx][-110:-14]
                    if b' '+zx not in d.keys():       return  10 # Error public key
                    k.pt = k.uncompress56(zx + d[b' '+zx])
                    if not k.verify(sig, msg):        return  11 # bad signature
        # Hash
        if len(x) == 8:
            h = ecc.z10
            for i in range(ecc.b2i(d[x][:4])):
                dx = x + ecc.i2b(i+1, 4)
                if len(d[dx]) in (NS, ND, NC):
                    rh = d[dx][-10:]
                    if len(d[dx]) == NS: dx = d[dx][:12]
                    msg = d[dx][:8] + dx[:8] + d[dx][8:-110]
                    h = hashlib.sha1(msg + h).digest()[:10]
                    if h != rh:                       return 12 # bad hash
        # Wealth
        if len(x) == 1: wr = ecc.b2i(d[x][8:])
        if len(x) == 8:
            for i in range(ecc.b2i(d[x][:4])):
                dx = x + ecc.i2b(i+1, 4)
                if len(d[dx]) == ND: wc += ecc.b2i(d[dx][20:24])       
        # Operations counter
        if len(x) == 1: tr = ecc.b2i(d[x][:8])
        if len(x) == 8:
            for i in range(ecc.b2i(d[x][:4])):
                dx = x + ecc.i2b(i+1, 4)
                if len(d[dx]) in (ND, NC): tc += 1
        # Balances
        if len(x) == 8:
            bal = 0
            for i in range(ecc.b2i(d[x][:4])):
                dx = x + ecc.i2b(i+1, 4)
                if dx not in d:                        return 13 # missing transaction
                if len(d[dx])   == ND: bal += ecc.b2i(d[x + ecc.i2b(i+1, 4)][20:24])
                elif len(d[dx]) == NS: bal -= ecc.b2i(d[d[dx][:12]][20:24])
            if bal != ecc.b2s(d[x][4:8], 4):           return 14 # bad balance
    if wc != wr:                                       return 15 # bad wealth
    if tc != tr:                                       return 16 # bad counter
    return 0 # everythink ok


def history(e, d):
    o = [e, ]
    x = ecc.z56decode(e)
    nt = ecc.b2i(d[x][:4])
    o.append( ('%04d operations' % nt).encode('UTF-8') )
    for i in range(nt):
        dx = x + ecc.i2b(i+1, 4)
        h = ecc.b2i(d[dx][-10:])
        zx = ecc.z56encode(d[dx][:8])
        bal = ecc.b2s(d[dx][-14:-10], 4)
        dat = ecc.datdecode(d[dx][8:12])
        if len(d[dx]) == NC:
            val = 0
            bal = ecc.b2s(d[dx][-14:-10], 4)        
            sg = b' '
        elif len(d[dx]) == ND:
            val = ecc.b2i(d[dx][20:24])
            bal = ecc.b2s(d[dx][-14:-10], 4)        
            sg = b'+'
        elif len(d[dx]) == NS:
            dx = d[dx][:12]
            bal = ecc.b2s(d[dx][-14:-10], 4)
            val = ecc.b2i(d[dx][20:24])
            dat = ecc.datdecode(d[dx][8:12])
            sg = b'-'
        o.append(b'%d %s%3d %06d H:%020X %s %s' % (i+1, sg, val, bal, h, zx, dat.encode('UTF-8')))
    o.append(b'Balance: %04d' % ecc.b2s(d[x][4:8], 4))
    return b'\n'.join(o)

def list(d):
    lu, lo = [x[1:] for x in d.keys() if len(x) == 13], []
    for p, i in enumerate(lu):
        x = ecc.z56decode(i)
        ct = (' %6d' % ecc.b2s(d[x][4:8], 4)).encode('UTF-8') if ecc.b2i(d[x][8:12]) > ecc.datint() else b''
        lo.append( ('%d ' % (p+1)).encode('UTF-8') + i + ct)
    return b'\n'.join(lo)   

def register85(e, d):
    """
    """
    if len(d.keys()) == 0: d[ecc.v1] = ecc.z8 + ecc.z8 # INIT
    zid, dl = ecc.z85encode(e[:8]), ecc.add1year(ecc.datencode()) if len(d.keys()) == 1 else ecc.z4
    for i in range(1, 11):
        if sum([1 for x in d.keys() if len(x) == 11]) < (85**i)//2: break
    for x in d.keys():
        if len(x) == 11 and x[1:i] == zid[:i]: return b'SOFT-COLISION! Please generate another id'
    if zid in d: return b'COLISION!'
    # START WRITING
    d[e[:8]] = ecc.z4 + ecc.zs4 + dl
    d[b' '+zid] = ecc.z85encode(e[8:])
    # STOP WRITING
    return zid + b' registered'

def register56(e, d):
    """
    """
    if len(d.keys()) == 0: d[ecc.v1] = ecc.z8 + ecc.z8 # INIT
    zid, dl = ecc.z56encode(e[:8]), ecc.add1year(ecc.datencode()) if len(d.keys()) == 1 else ecc.z4
    for i in range(1, 13):
        if sum([1 for x in d.keys() if len(x) == 13]) < (56**i)//2: break
    for x in d.keys():
        if len(x) == 13 and x[1:i] == zid[:i]: return b'SOFT-COLISION! Please generate another id'
    if zid in d: return b'COLISION!'
    # START WRITING
    d[e[:8]] = ecc.z4 + ecc.zs4 + dl
    d[b' '+zid] = ecc.z56encode(e[8:])
    # STOP WRITING
    return zid + b' registered'

def invoice(e, d):
    return b'invoice'

def transaction(e, d):
    """
    """
    src, dst, dat, lat, mnt, ref = e[:8], e[8:16], e[16:20], e[20:28], e[28:32], e[32:40]
    msg, sig, now = e[:-96], e[-96:], ecc.datint()
    if src not in d.keys() or dst not in d.keys() or src == dst:           return b'Error database'
    dls, dld = d[src][8:12], d[dst][8:12]
    zx, zd = ecc.z56encode(src), ecc.z56encode(dst)
    if b' '+zx not in d.keys():                                            return b'Error public key'
    k.pt = k.uncompress56(zx + d[b' '+zx])
    if not k.verify(sig, msg):                                             return b'Error signature'    
    val, bals, bald = ecc.b2i(mnt), ecc.b2s(d[src][4:8], 4), ecc.b2s(d[dst][4:8], 4)
    if val <= 0 or bals - val < -MAXB or bald + val > MAXB:                return b'Error value'
    os, od = ecc.b2i(d[src][:4]), ecc.b2i(d[dst][:4])
    ns, nd = os + 1, od + 1
    nhs = ecc.z10 if os == 0 else d[src + ecc.i2b(os, 4)][-10:]
    nhd = ecc.z10 if od == 0 else d[dst + ecc.i2b(od, 4)][-10:]
    hs, hd = hashlib.sha1(msg + nhs).digest()[:10], hashlib.sha1(msg + nhd).digest()[:10]
    lst_tot, lst_wlt = ecc.b2i(d[ecc.v1][:8]), ecc.b2i(d[ecc.v1][8:])
    if ecc.b2i(dls) <= now or ecc.b2i(dld) <= now or ecc.b2i(dat) > now:   return b'Error deadline'    
    if os > 0:
        dx = src + ecc.i2b(os, 4)
        if len(d[dx]) == NS: dx = d[dx][:12]
        if ecc.b2i(d[dx][8:12]) >= ecc.b2i(dat):                           return b'Wait a minute !'
    nws, nwd = ecc.s2b(bals - val, 4), ecc.s2b(bald + val, 4)
    # BEGIN WRITE SECTION
    d[src] = ecc.i2b(ns, 4)  + nws + dls
    d[src  + ecc.i2b(ns, 4)] = dst + ecc.i2b(nd, 4) + nws + hs
    d[dst] = ecc.i2b(nd, 4)  + nwd + dld
    d[dst  + ecc.i2b(nd, 4)] = src + dat + lat + mnt + ref + sig + nwd + hd
    d[ecc.v1] = ecc.i2b(lst_tot + 1, 8) + ecc.i2b(lst_wlt + val, 8)
    # END WRITE SECTION
    return b'TRANSACTION from ' + zx + b' to ' + zd    

def certificate(e, d):
    """
    A(green) if first
    B->A if A(green)B(red)    then B(orange)
    A->B if A(green)B(orange) then B(green)
    """
    src, dst, dat, lat, pld, ref = e[:8], e[8:16], e[16:20], e[20:28], e[28:38], e[38:46]
    msg, sig, now = e[:-96], e[-96:], ecc.datint()
    if ecc.b2i(dat) > now:                                             return b'future date'
    if src not in d.keys() or dst not in d.keys() or src == dst:       return b'Error database'
    dl_s, dl_d = d[src][8:12], d[dst][8:12]
    zx = ecc.z56encode(src)
    if b' '+zx not in d.keys():                                        return b'Error public key'
    k.pt = k.uncompress56(zx + d[b' '+zx])
    if not k.verify(sig, msg):                                         return b'Error signature'
    green, orang, red = ecc.add1year(ecc.datencode()), ecc.datencode(), ecc.z4
    os, od = ecc.b2i(d[src][:4]), ecc.b2i(d[dst][:4])
    ns, nd = os + 1, od + 1
    nhs = ecc.z10 if os == 0 else d[src + ecc.i2b(os, 4)][-10:]
    nhd = ecc.z10 if od == 0 else d[dst + ecc.i2b(od, 4)][-10:]
    hs, hd = hashlib.sha1(msg + nhs).digest()[:10], hashlib.sha1(msg + nhd).digest()[:10]
    if os > 0:
        dx = src + ecc.i2b(os, 4)
        if len(d[dx]) == NS: dx = d[dx][:12]
        if ecc.b2i(d[dx][8:12]) >= ecc.b2i(dat):                       return b'Wait a minute !'
    # START WRITING
    if ecc.b2i(d[dst][8:12]) > ecc.datint() and d[src][8:12] == red:
        d[src] = d[src][:8] + orang
        d[dst] = ecc.i2b(nd, 4) + d[dst][4:12]
        d[dst  + ecc.i2b(nd, 4)] = src + dat + lat + pld + ref + sig + ecc.z4 + hd
        d[ecc.v1] = ecc.i2b(ecc.b2i(d[ecc.v1][:8]) + 1, 8) + d[ecc.v1][8:]
        return b'REQUEST by ' + zx
    if ecc.b2i(d[src][8:12]) > ecc.datint() and d[dst][8:12] != red:
        d[dst] = ecc.i2b(nd, 4) + d[dst][4:8] + green
        d[dst  + ecc.i2b(nd, 4)] = src + dat + lat + pld + ref + sig + ecc.z4 + hd
        d[ecc.v1] = ecc.i2b(ecc.b2i(d[ecc.v1][:8]) + 1, 8) + d[ecc.v1][8:]
        return b'CERTIFICATION by ' + zx
    # STOP WRITING
    else:                                                               return b'Error request'

def server(db, ip):
    """ 
    """
    s.bind((ip, PORT))
    print ('IO-server on %s' % ip)    
    with dbm.open(db, 'c') as d:
        if ecc.v1 in d.keys():
            print ('Wealth: %d [%d operations]' % (ecc.b2i(d[ecc.v1][8:]),ecc.b2i(d[ecc.v1][:8]) ))   
    while True:
        (data, addr), o = s.recvfrom(1024), b''
        with dbm.open(db, 'c') as d:
            if       data  == b'l': o = list(d)
            elif len(data) ==   12: o = history    (data, d)
            elif len(data) ==   48: o = register56 (data, d)
            elif len(data) ==  136: o = transaction(data, d)
            elif len(data) ==  142: o = certificate(data, d)
            elif len(data) >=  144 and len(data) <= 256: o = invoice(data, d)
            elif     data  == b'c':
                err = check(d)
                if err: o = ('ERROR %d' % err).encode('UTF-8') 
            else: o = b'command not found!'
            s.sendto(o, addr)
    
def get_my(sel):
    if os.path.isfile('lpub'):
        with open('lpub') as f:
            all = [leaf.reg.v.group(1) for l in f if leaf.reg(re.match('%s (\S{12})' % sel, l))]
            return all[0].encode('UTF-8') if all else b''
    else: return b''
        
def client(db, ip):
    " Simulate smart-phone with strong authentication "
    my = b''
    while True:
        if my == b'': my = get_my('1')
        cmd, req = input('%s >' % my.decode('UTF-8')), b''
        if re.match('(r|reg|register)\s*$', cmd): # 48
            k.generate()
            sk, pk = ecc.z56encode(ecc.i2b(k.privkey, 48)), k.compress56(k.pt)
            req = ecc.z56decode(pk)
            with dbm.open(db, 'c') as d: d[pk[:12]] = pk[12:] + sk
        elif re.match('(c|chk|check)\s*$',    cmd): req = b'c'
        elif re.match('(l|ls|list)\s*$',      cmd): req = b'l'
        elif re.match('(h|hist|history)\s*$', cmd): req = my
        elif leaf.reg(re.match('(my|)\s*(\d{1,2})\s*$', cmd)): my = get_my(leaf.reg.v.group(2))
        elif leaf.reg(re.match('(p|pay)\s*(\d{1,2})\s+(\d{1,3})\s*$', cmd)): # 136
            with dbm.open(db) as d:
                if my in d.keys():
                    pk, sk, val = my + d[my][:60], d[my][60:], leaf.reg.v.group(3)
                    src, dst = ecc.z56decode(pk[:12]), ecc.z56decode(get_my(leaf.reg.v.group(2)))
                    k.pt, k.privkey = k.uncompress56(pk), ecc.b2i(ecc.z56decode(sk))
                    msg = src + dst + ecc.datencode() + ecc.z8 + ecc.i2b(int(val), 4) + ecc.z8 # len:40
                    req = msg + k.sign(msg)
        elif leaf.reg(re.match('(c|crt|cert)\s*(\d{1,2})\s*$', cmd)): # len:142
            with dbm.open(db) as d:
                if my in d.keys():
                    pk, sk = my + d[my][:60], d[my][60:]
                    src, dst = ecc.z56decode(pk[:12]), ecc.z56decode(get_my(leaf.reg.v.group(2)))
                    k.pt, k.privkey = k.uncompress56(pk), ecc.b2i(ecc.z56decode(sk))
                    msg = src + dst + ecc.datencode() + ecc.z8 + ecc.z10 + ecc.z8 # len 46
                    req = msg + k.sign(msg)
        elif cmd == 'end':
            s.close()
            break
        if req:
            s.sendto(req, (ip, PORT))
            data, addr = s.recvfrom(1024)
            if data:
                print (data.decode('UTF-8'))
                if req == b'l':
                    with open('lpub', 'w') as lp: lp.write(data.decode('UTF-8'))

import readline, subprocess

if __name__ == "__main__":
    # client('local', '127.0.0.1')
    # server('base' , '127.0.0.1')
    client('local', sys.argv[1]) if len(sys.argv) == 2 else server('base', leaf.ip())

    #print(p.stdout.readlines())

    
# end
