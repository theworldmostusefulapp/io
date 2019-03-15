#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
IO-PROTOCOL over UDP (client and server) v0.1

1/ IO DB FORMAT
DBHEAD: 01:016 IO_VER(1)       : TOTAL_NC(8)  WEALTH(8)      
S_HEAD: 08:008 SRC(8)          : LST_N_SRC(4) DEADLINE_SRC(4)
D_HEAD: 08:008 DST(8)          : LST_N_DST(4) DEADLINE_DST(4)

PUBKEY: 16:080     ID(16)      : PUBLIC_KEY_END(80)[base16]

TRANSATION 
TR_SRC: 12:026 SRC(8) N_SRC(4) : DST(8) N_DST(4)                                   BAL(4) H(10)
TR_DST: 12:142 DST(8) N_DST(4) : SRC(8)   DAT(4) LATLONG(8) MNT(4)  REF(8) SIG(96) BAL(4) H(10)
CERTIF: 12:148 SRC(8) N_SRC(4) : DST(8)   DAT(4) LATLONG(8) PLD(10) REF(8) SIG(96) BAL(4) H(10)

INVOIC: 12:148 SRC(8) N_SRC(4) : DST(8) DAT(4) LATLONG(8) HIST(16)  H(10) SIG(96)
        12:256                                            HIST(130)              

2/ API 
REGISTER(48):     pk(48)
CERTIFICATE(134): msg(38)+sig(96)
TRANSACTION(128): msg(32)+sig(96)

3/ TODO LIST
- Subporcess Test Automation
- PyTorch setup
"""
import sys, os, socket, ecc, dbm, re, hashlib, leaf

#import torch
#print (torch.rand(5, 3))
#import tensorflow

s, k, MAXB, PORT = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), ecc.ecdsa(), 1000, 7800
NS, ND, NC = 26, 142, 148

def verif(d):
    """
    make it differential
    check certification !
    """
    print ('run check!')
    if len(d.keys()) > 0 and ecc.v1 not in d:           return 0x01 # head does not exists 
    wc, wr, tc, tr, al = 0, 0, 0, 0, 0
    for x in d.keys():
        # Length
        lk, lv = len(x), len(d[x])
        if lk == 1: wr, tr = ecc.b2i(d[x][8:]), ecc.b2i(d[x][:8])
        if lk == 1  and lv != 16:                       return 0x02 # bad length head
        if lk == 8  and lv !=  8:                       return 0x03 # bad length id head 
        if lk == 12 and lv not in (NS, ND, NC):         return 0x05 # bad length operation
        if lk == 16 and lv != 80:                       return 0x04 # bad length pub key
        # Public keys
        if lk == 12:
            if ecc.b2h(x[:8])    not in d:              return 0x06 # src id unknown
            if ecc.b2h(d[x][:8]) not in d:              return 0x07 # dst id unknown 
        if lk == 8:
            # Money supply
            al += balance(x, d)
            # Dates
            dat = ecc.z8
            for i in range(ecc.b2i(d[x][:4])):
                dx = x + ecc.i2b(i+1, 4)
                if len(d[dx]) in (ND, NC):
                    if    d[dx][8:12] <= dat:           return 0x08 # bad date increase
                    dat = d[dx][8:12]
                if len(d[dx]) == ND:
                    if dat > d[x][4:]:                  return 0x09 # invalid date/dead line
            # Signatures
            for i in range(ecc.b2i(d[x][:4])):
                dx = x + ecc.i2b(i+1, 4)
                if len(d[dx]) == NC: src, dst = x,         d[dx][:8]
                if len(d[dx]) == ND: src, dst = d[dx][:8], dx[:8]
                if len(d[dx]) in (NC, ND):
                    zx = ecc.b2h(src)
                    if zx not in d.keys():              return 0x0A # Error public key                    
                    msg, sig = src + dst + d[dx][8:-110], d[dx][-110:-14]
                    k.pt = k.uncompress(ecc.h2b(zx + d[zx]))
                    if not k.verify(sig, msg):          return 0x0B # bad signature
            # Hash
            h = ecc.z10
            for i in range(ecc.b2i(d[x][:4])):
                dx = x + ecc.i2b(i+1, 4)
                h = hashlib.sha1(x + d[dx][:-10] + h).digest()[:10]
                if h != d[dx][-10:]:                    return 0x0C # bad hash
            # Wealth
            for i in range(ecc.b2i(d[x][:4])):
                dx = x + ecc.i2b(i+1, 4)
                if len(d[dx]) == ND: wc += ecc.b2i(d[dx][20:24])       
            # Operations counter
            for i in range(ecc.b2i(d[x][:4])):
                dx = x + ecc.i2b(i+1, 4)
                if len(d[dx]) in (ND, NC): tc += 1
            # Balances
            b = 0
            for i in range(ecc.b2i(d[x][:4])):
                dx = x + ecc.i2b(i+1, 4)
                if dx not in d:                         return 0x0D # missing transaction
                if len(d[dx])   == ND: b += ecc.b2i(d[x + ecc.i2b(i+1, 4)][20:24])
                elif len(d[dx]) == NS: b -= ecc.b2i(d[d[dx][:12]][20:24])
                if b != ecc.b2s(d[dx][-14:-10], 4):     return 0x0E # bad balance
    if wc != wr:                                        return 0x10 # bad wealth
    if tc != tr:                                        return 0x11 # bad counter
    if al != 0:                                         return 0x12 # bad money supply
    return 0 # Everythink ok !

def balance(x, d):
    ""
    n = ecc.b2i(d[x][:4])
    if n == 0: return 0
    return ecc.b2s(d[x + ecc.i2b(n, 4)][-14:-10], 4)  

def history(e, d):
    ""
    x = ecc.h2b(e)
    n = ecc.b2i(d[x][:4])
    o = [e + b' nb: %04d balance: %6d' % (n, balance(x, d))]
    for i in range(n):
        dx = x + ecc.i2b(i+1, 4)
        h, zx, y = ecc.b2i(d[dx][-10:]), ecc.b2h(d[dx][:8]), d[dx]
        bal = ecc.b2s(y[-14:-10], 4)
        if len(y) == NS: dx = d[dx][:12]
        if len(y) == NC: val, sg, dat = 0, b' ', ecc.datdecode(d[dx][8:12])
        elif len(y) == ND:
            val = ecc.b2i(d[dx][20:24])
            dat = ecc.datdecode(d[dx][8:12])
            sg = b'+'
        elif len(y) == NS:
            val = ecc.b2i(d[dx][20:24])
            dat = ecc.datdecode(d[dx][8:12])
            sg = b'-'
        o.append(b'%03d %s%3d %8d H:%020X %s %s' % (i+1, sg, val, bal, h, zx, dat.encode('UTF-8')))
    o.append(b'Balance: %6d' % balance(x, d) )
    return b'\n'.join(o)

def list(d):
    ""
    lu, lo = [x for x in d.keys() if len(x) == 16], []
    for p, i in enumerate(lu):
        x = ecc.h2b(i)
        ct = (' %6d' % balance(x, d)).encode('UTF-8') if ecc.b2i(d[x][4:]) > ecc.datint() else b''
        lo.append( ('%d\t' % (p+1)).encode('UTF-8') + i + ct)
    return b'\n'.join(lo)   

def register(e, d):
    """
    """
    if len(d.keys()) == 0: d[ecc.v1] = ecc.z8 + ecc.z8 # INIT
    zid, dl = ecc.b2h(e[:8]), ecc.add1year(ecc.datencode()) if len(d.keys()) == 1 else ecc.z4
    for i in range(1, 16):
        if sum([1 for x in d.keys() if len(x) == 16]) < (16**i)//2: break
    for x in d.keys():
        if len(x) == 16 and x[:i] == zid[:i]:
            return ('%s COLISION [%d] -> re-run generation !' % (zid, i)).encode('UTF-8')
    if zid in d: return b'COLISION!'
    # START WRITING
    d[e[:8]] = ecc.z4 + dl
    d[zid] = ecc.b2h(e[8:])
    # STOP WRITING
    return zid + b' registered'

def invoice(e, d):
    ""
    return b'invoice'

def transaction(e, d):
    """
    """
    src, dst, dat, lat, mnt, ref = e[:8], e[8:16], e[16:20], e[20:28], e[28:32], e[32:40]
    msg, sig, now = e[:-96], e[-96:], ecc.datint()
    if src not in d.keys() or dst not in d.keys() or src == dst:         return b'Error database'
    dls, dld = d[src][4:], d[dst][4:]
    zx, zd = ecc.b2h(src), ecc.b2h(dst)
    if zx not in d.keys():                                               return b'Error public key'
    k.pt = k.uncompress(ecc.h2b(zx + d[zx]))
    if not k.verify(sig, msg):                                           return b'Error signature'    
    val, bals, bald = ecc.b2i(mnt), balance(src, d), balance(dst, d)
    if val <= 0 or bals - val < -MAXB or bald + val > MAXB:              return b'Error value'
    os, od = ecc.b2i(d[src][:4]), ecc.b2i(d[dst][:4])
    ns, nd = os + 1, od + 1
    nhs = ecc.z10 if os == 0 else d[src + ecc.i2b(os, 4)][-10:]
    nhd = ecc.z10 if od == 0 else d[dst + ecc.i2b(od, 4)][-10:]
    lst_tot, lst_wlt = ecc.b2i(d[ecc.v1][:8]), ecc.b2i(d[ecc.v1][8:])
    if ecc.b2i(dls) <= now or ecc.b2i(dld) <= now or ecc.b2i(dat) > now: return b'Error deadline'    
    if os > 0:
        dx = src + ecc.i2b(os, 4)
        if len(d[dx]) == NS: dx = d[dx][:12]
        if ecc.b2i(d[dx][8:12]) >= ecc.b2i(dat):                         return b'Wait a minute !'
    nws, nwd = ecc.s2b(bals - val, 4), ecc.s2b(bald + val, 4)
    sm, dm = dst + ecc.i2b(nd, 4) + nws, src + dat + lat + mnt + ref + sig + nwd
    # BEGIN WRITE SECTION
    d[src] = ecc.i2b(ns, 4)  + dls
    d[src  + ecc.i2b(ns, 4)] = sm + hashlib.sha1(src + sm + nhs).digest()[:10]
    d[dst] = ecc.i2b(nd, 4)  + dld
    d[dst  + ecc.i2b(nd, 4)] = dm + hashlib.sha1(dst + dm + nhd).digest()[:10]
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
    zx = ecc.b2h(src)
    if zx not in d.keys():                                             return b'Error public key'
    k.pt = k.uncompress(ecc.h2b(zx + d[zx]))
    if not k.verify(sig, msg):                                         return b'Error signature'
    green, orang, red = ecc.add1year(ecc.datencode()), ecc.datencode(), ecc.z4
    os, od = ecc.b2i(d[src][:4]), ecc.b2i(d[dst][:4])
    ns, nd = os + 1, od + 1
    nhs = ecc.z10 if os == 0 else d[src + ecc.i2b(os, 4)][-10:]
    if os > 0:
        dx = src + ecc.i2b(os, 4)
        if len(d[dx]) == NS: dx = d[dx][:12]
        if ecc.b2i(d[dx][8:12]) >= ecc.b2i(dat):                       return b'Wait a minute !'
    nws = ecc.s2b(balance(src, d), 4)
    sm = dst + dat + lat + pld + ref + sig + nws
    # START WRITING
    if ecc.b2i(d[dst][4:]) > ecc.datint() and d[src][4:] == red:
        d[src] = ecc.i2b(ns, 4) + orang
        d[src  + ecc.i2b(ns, 4)] = sm + hashlib.sha1(src + sm + nhs).digest()[:10]
        d[ecc.v1] = ecc.i2b(ecc.b2i(d[ecc.v1][:8]) + 1, 8) + d[ecc.v1][8:]
        return b'REQUEST by ' + zx
    if ecc.b2i(d[src][4:]) > ecc.datint() and d[dst][4:] != red:
        d[dst] = d[dst][:4] + green
        d[src] = ecc.i2b(ns, 4) + d[src][4:]       
        d[src  + ecc.i2b(ns, 4)] = sm + hashlib.sha1(src + sm + nhs).digest()[:10]
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
            elif leaf.reg(re.match(b'(\S+)\s', data)):
                mel = leaf.reg.v.group(1)
                ky = data[len(mel)+1:]
                with dbm.open('mel', 'c') as m:
                    if mel not in m and len(ky) == 48: o = register(ky, d)                    
                    m[mel] = ecc.b2h(ky[:8])
            elif len(data) ==   16: o = history    (data, d)
            elif len(data) ==  136: o = transaction(data, d)
            elif len(data) ==  142: o = certificate(data, d)
            elif len(data) >=  144 and len(data) <= 256: o = invoice(data, d)
            elif     data  == b'v':
                err = verif(d)
                if err: o = ('ERROR %02X' % err).encode('UTF-8') 
            else: o = b'command not found!'
            s.sendto(o, addr)
    
def get_my(sel):
    ""
    if os.path.isfile('lpub'):
        with open('lpub') as f:
            all = [leaf.reg.v.group(1) for l in f if leaf.reg(re.match('%s\s+(\S{16})' % sel, l))]
            return all[0].encode('UTF-8') if all else b''
    else: return b''

def gene(bmy, dst, pld, d):
    ""
    if bmy in d.keys():
        pk, sk = bmy + d[bmy][:40], d[bmy][40:]
        k.pt, k.privkey = k.uncompress(pk), ecc.b2i(sk)
        msg = pk[:8] + dst + ecc.datencode() + ecc.z8 + pld + ecc.z8 
        return msg + k.sign(msg)
    else:
        print ('you do not own that key')
        return b''

def genkey(mel, unik, d):
    if len(d.keys()) > 0 and unik:
        print ('key already defined')
        return b''
    k.generate()
    sk, pk = ecc.i2b(k.privkey, 48), k.compress(k.pt)
    d[pk[:8]] = pk[8:] + sk
    return mel + b' ' + pk
    
def client(db, ip, unik=False):
    " Simulate smart-phone with strong authentication "
    my = b''
    while True:
        if my == b'': my = get_my('1')
        cmd, req, bmy = input('%s >' % my.decode('UTF-8')), b'', ecc.h2b(my)
        if leaf.reg(re.match('(r|reg|register)\s*(\w+@\w+\.\w+)\s*$', cmd)): # 48
            with dbm.open(db, 'c') as d:
                req = genkey(leaf.reg.v.group(2).encode('UTF-8'), unik, d)
        elif re.match('(v|verif|verification)\s*$', cmd): req = b'v'
        elif re.match('(l|ls|list)\s*$',            cmd): req = b'l'
        elif re.match('(h|hist|history)\s*$',       cmd): req = my
        elif leaf.reg(re.match('(my|)\s*(\d{1,2})\s*$', cmd)): my = get_my(leaf.reg.v.group(2))
        elif leaf.reg(re.match('(p|pay)\s*(\d{1,2})\s+(\d{1,3})\s*$', cmd)): # 136
            with dbm.open(db) as d:
                pld = ecc.i2b(int(leaf.reg.v.group(3)), 4)
                req = gene(bmy, ecc.h2b(get_my(leaf.reg.v.group(2))), pld, d)
        elif leaf.reg(re.match('(c|crt|cert)\s*(\d{1,2})\s*$', cmd)): # len:142
            with dbm.open(db) as d:
                req = gene(bmy, ecc.h2b(get_my(leaf.reg.v.group(2))), ecc.z10, d)
        elif cmd == 'end':
            s.close()
            break
        if req:
            s.sendto(req, (ip, PORT))
            data, addr = s.recvfrom(2048)
            if data:
                print (data.decode('UTF-8'))
                if req == b'l':
                    with open('lpub', 'w') as lp: lp.write(data.decode('UTF-8'))
                    
import readline, subprocess

if __name__ == "__main__":
    # client('local', '127.0.0.1')
    # server('base' , '127.0.0.1')
    client('local', sys.argv[1], True) if len(sys.argv) == 2 else server('base', leaf.ip())

    #print(p.stdout.readlines())

    
# end
