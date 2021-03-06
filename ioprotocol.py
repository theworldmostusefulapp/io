#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
IO-PROTOCOL over UDP/IP (client and server) v0.1

1/ IO-PROTOCOL is between three parts:
- Humans (represented by their smartphone)                                -> 'phone'  proc
- Objects/Robots/IAs (limited memory and only local (BLE,NFC) connection) -> 'object' proc
- Internet servers                                                        -> 'server' proc

An UDP socket on port 7800 links Human (client) and Internet (server)
An UDP socket on port 7801 links Human (client) and Object   

2/ IO DB FORMAT
DBHEAD: 01:016 IO_VER(1)       : TOTAL_NC(8)  WEALTH(8)      
S_KEYS: 05:096 SERVER(5)       : SERVER_PUB_KEY(48) SERVER_PRIVATE_KEY(48)

S_HEAD: 08:008 SRC(8)          : LST_N_SRC(4) DEADLINE_SRC(4)
D_HEAD: 08:008 DST(8)          : LST_N_DST(4) DEADLINE_DST(4)

PUBKEY: 16:080 ID(16)          : PUBLIC_KEY_END(80)[base16]

TRANSATION 
TR_SRC: 12:026 SRC(8) N_SRC(4) : DST(8) N_DST(4)                                   BAL(4) H(10)
TR_DST: 12:142 DST(8) N_DST(4) : SRC(8)   DAT(4) LATLONG(8) MNT(4)  REF(8) SIG(96) BAL(4) H(10)
CERTIF: 12:148 SRC(8) N_SRC(4) : DST(8)   DAT(4) LATLONG(8) PLD(10) REF(8) SIG(96) BAL(4) H(10)

INVOIC: 12:148 SRC(8) N_SRC(4) : DST(8) DAT(4) LATLONG(8) HIST(16)  H(10) SIG(96)
        12:256                                            HIST(130)              

3/ API 
REGISTER(48):     email + pk(48)
CERTIFICATE(136): msg(40)+sig(96)
TRANSACTION(142): msg(46)+sig(96)

4/ TODO LIST
- Subprocess Test Automation
- PyTorch setup
- differential verification
- follow certification web of trust
- HTTP(S) encapsulation
"""
import sys, os, socket, ecc, dbm, re, hashlib, leaf, threading, time, random
import readline # for command history

# PROVISION
#import torch
#import subprocess

MAXBAL = 1000 
PORT1, PORT2 = 7800, 7801
NS, ND, NC = 26, 142, 148

def verif(d):
    """
    check certification !
    """
    print ('run check!')
    k = ecc.ecdsa()
    if len(d.keys()) > 0 and ecc.v1 not in d:           return 0x01 # head does not exists 
    wc, wr, tc, tr, al = 0, 0, 0, 0, 0

    lo = []
    for i in [x for x in d.keys() if len(x) == 16]:
        x = ecc.h2b(i)
        if ecc.b2i(d[x][4:]) > ecc.datint(): lo.append(x)
    #print (lo)
    #find the root
    
    for x in d.keys():
        # Length
        lk, lv = len(x), len(d[x])
        if lk == 1: wr, tr = ecc.b2i(d[x][8:16]), ecc.b2i(d[x][:8])
        if lk == 1  and lv != 16:                       return 0x02 # bad length head
        if lk == 5  and lv != 96:                       return 0x03 # bad length server id
        if lk == 8  and lv !=  8:                       return 0x04 # bad length id head 
        if lk == 12 and lv not in (NS, ND, NC):         return 0x05 # bad length operation
        if lk == 16 and lv != 80:                       return 0x06 # bad length pub key
        # Public keys
        if lk == 12:
            if ecc.b2h(x[:8])    not in d:              return 0x07 # src id unknown
            if ecc.b2h(d[x][:8]) not in d:              return 0x08 # dst id unknown 
        if lk == 8:
            # Money supply
            al += balance(x, d)
            # Dates
            dat = ecc.z8
            for i in range(ecc.b2i(d[x][:4])):
                dx = x + ecc.i2b(i+1, 4)
                if len(d[dx]) in (ND, NC):
                    if    d[dx][8:12] <= dat:           return 0x09 # bad date increase
                    dat = d[dx][8:12]
                if len(d[dx]) == ND:
                    if dat > d[x][4:]:                  return 0x0A # invalid date/dead line
            # Signatures
            for i in range(ecc.b2i(d[x][:4])):
                dx = x + ecc.i2b(i+1, 4)
                if len(d[dx]) == NC: src, dst = x,         d[dx][:8]
                if len(d[dx]) == ND: src, dst = d[dx][:8], dx[:8]
                if len(d[dx]) in (NC, ND):
                    zx = ecc.b2h(src)
                    if zx not in d.keys():              return 0x0B # Error public key                    
                    msg, sig = src + dst + d[dx][8:-110], d[dx][-110:-14]
                    k = ecc.ecdsa()
                    k.pt = k.uncompress(ecc.h2b(zx + d[zx]))
                    if not k.verify(sig, msg):          return 0x0C # bad signature
            # Hash
            h = ecc.z10
            for i in range(ecc.b2i(d[x][:4])):
                dx = x + ecc.i2b(i+1, 4)
                h = hashlib.sha1(x + d[dx][:-10] + h).digest()[:10]
                if h != d[dx][-10:]:                    return 0x0D # bad hash
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
                if dx not in d:                         return 0x0E # missing transaction
                if len(d[dx])   == ND: b += ecc.b2i(d[x + ecc.i2b(i+1, 4)][20:24])
                elif len(d[dx]) == NS: b -= ecc.b2i(d[d[dx][:12]][20:24])
                if b != ecc.b2s(d[dx][-14:-10], 4):     return 0x0F # bad balance
                if b < -MAXBAL or b > MAXBAL:           return 0x10 # Out of bounds
    if wc != wr:                                        return 0x11 # bad wealth
    if tc != tr:                                        return 0x12 # bad counter
    if al != 0:                                         return 0x13 # bad money supply
    return 0 # Everythink ok !

def balance(x, d):
    ""
    n = ecc.b2i(d[x][:4])
    if n == 0: return 0
    return ecc.b2s(d[x + ecc.i2b(n, 4)][-14:-10], 4)  

def proof(x, d):
    ""
    if b'SERVER' in d.keys():
        k = ecc.ecdsa()
        pk, sk = d[b'SERVER'][:48], d[b'SERVER'][48:]
        k.pt, k.privkey = k.uncompress(pk), ecc.b2i(sk)
        dat = ecc.datdecode(ecc.datencode()).encode('UTF-8')
        msg = b'%s %d %s' % (ecc.b2h(x), balance(x, d), dat)
        return ecc.z85encode(k.sign(msg)) + msg if not verif(d) else b'error'
    return b''

def server_id(d):
    ""
    return ecc.z85encode(d[b'SERVER'][:48]) if b'SERVER' in d.keys() else b''

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

def list_humans(d):
    ""
    lu, lo = [x for x in d.keys() if len(x) == 16], []
    for p, i in enumerate(lu):
        x = ecc.h2b(i)
        ct = (' %6d' % balance(x, d)).encode('UTF-8') if ecc.b2i(d[x][4:]) > ecc.datint() else b''
        perso = b'' # provision
        lo.append( ('%d\t' % (p+1)).encode('UTF-8') + i + ct + perso)
    return b'\n'.join(lo)   

def candidate(data, d):
    ky, mel , o = data[:48], data[48:], b''
    with dbm.open('mel', 'c') as m:
        if mel not in m:
            o = register(ky, d)
            if o[:8] != b'COLISION': m[mel] = ecc.b2h(ky[:8])
    return o

def register(e, d):
    ""
    zid, dl = ecc.b2h(e[:8]), ecc.add1year(ecc.datencode()) if len(d.keys()) == 2 else ecc.z4
    for i in range(1, 16):
        if sum([1 for x in d.keys() if len(x) == 16]) < (16**i)//2: break
    for x in d.keys():
        if len(x) == 16 and x[:i] == zid[:i]:
            return ('COLISION %s [%d] -> re-run generation !' % (zid, i)).encode('UTF-8')
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
    k = ecc.ecdsa()
    src, dst, dat, lat, mnt, ref = e[:8], e[8:16], e[16:20], e[20:28], e[28:32], e[32:40]
    msg, sig, now = e[:-96], e[-96:], ecc.datint()
    if src not in d.keys() or dst not in d.keys() or src == dst:         return b'Error database'
    dls, dld = d[src][4:], d[dst][4:]
    zx, zd = ecc.b2h(src), ecc.b2h(dst)
    if zx not in d.keys():                                               return b'Error public key'
    k.pt = k.uncompress(ecc.h2b(zx + d[zx]))
    if not k.verify(sig, msg):                                           return b'Error signature'    
    val, bals, bald = ecc.b2i(mnt), balance(src, d), balance(dst, d)
    if val <= 0 or bals - val < -MAXBAL or bald + val > MAXBAL:          return b'Error value'
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
    k = ecc.ecdsa()
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
        d[ecc.v1] = ecc.i2b(ecc.b2i(d[ecc.v1][:8]) + 1, 8) + d[ecc.v1][8:16]
        return b'CERTIFICATION by ' + zx
    # STOP WRITING
    else:                                                               return b'Error request'

def server(db, ip):
    """ 
    """
    k = ecc.ecdsa()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, PORT1))
    print ('IO-server on %s' % ip)
    with dbm.open(db, 'c') as d:
        if len(d.keys()) == 0:
            k.generate()
            sk, pk = ecc.i2b(k.privkey, 48), k.compress(k.pt)
            d[b'SERVER'] = pk + sk
            d[ecc.v1] = ecc.z8 + ecc.z8
            with open('server_pk', 'w') as f: f.write(ecc.z85encode(pk).decode('UTF-8'))
        print ('Server Public ID: ' + server_id(d).decode('UTF-8'))
        if ecc.v1 in d.keys():
            print ('Wealth: %d [%d operations]' % (ecc.b2i(d[ecc.v1][8:]),ecc.b2i(d[ecc.v1][:8]) ))   
    while True:
        (data, addr), o = s.recvfrom(1024), b''
        with dbm.open(db, 'c') as d:
            if len(data) == 1:
                if   data == b'v': o = b'Error %02X' % verif(d)
                elif data == b'l': o = list_humans(d)
                elif data == b's': o = server_id(d)
            elif len(data) ==    8: o = proof      (data, d)
            elif len(data) ==   16: o = history    (data, d)
            elif len(data) ==   93: o = candidate  (data, d)
            elif len(data) ==  136: o = transaction(data, d)
            elif len(data) ==  142: o = certificate(data, d)
            elif len(data) >=  144 and len(data) <= 256: o = invoice(data, d)
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
        k = ecc.ecdsa()
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
    k = ecc.ecdsa()
    k.generate()
    sk, pk = ecc.i2b(k.privkey, 48), k.compress(k.pt)
    d[pk[:8]] = pk[8:] + sk
    return pk + b'%45s' % mel

def phone(db, ip, unik=False):
    """ 
    IO CLIENT:
    Simulate smart-phone with strong authentication 
    Commands:
    l       -> list index of all registered bodies
    r email -> register a new body with a new email
    <num>   -> select <num> as current body
    v       -> verify all the database
    s       -> return server public id
    o       -> return proof of balance at current time, to give to offline objects
    c <num> -> request certificate to <num> or generate certificate for <num>
    p <num> <val> -> pay <num> body <val> amount of leaf
    h       -> display history for current body
    m       -> list all client ids (usually one if flag unik is True)
    b       -> begin counting resource by object
    e       -> end counting resource by object
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print ('IO Client (Phone)\nType ? for help')
    my = b''
    while True:
        if my == b'': my = get_my('1')
        cmd, req, bmy = input('%s >' % my.decode('UTF-8')), b'', ecc.h2b(my)
        if leaf.reg(re.match('(r|reg|register)\s*(\w{2,20}@\w{2,20}\.\w{2,3})\s*$', cmd)): # 48
            with dbm.open(db, 'c') as d:
                req = genkey(leaf.reg.v.group(2).encode('UTF-8'), unik, d)
        elif re.match('(v|verif|verification)\s*$', cmd): req = b'v'
        elif re.match('(l|ls|list)\s*$',            cmd): req = b'l'
        elif re.match('(s|server)\s*$',             cmd): req = b's'
        elif re.match('(h|hist|history)\s*$',       cmd): req = my
        elif re.match('(o|proof)\s*$',              cmd): req = bmy
        elif re.match('(\?|help)\s*$',              cmd): req = b''; print (__doc__, phone.__doc__)
        elif re.match('(b|begin|start)\s*$',        cmd): req = b''; start_access()
        elif re.match('(e|end|stop)\s*$',           cmd): req = b''; stop_access()
        elif leaf.reg(re.match('(my|)\s*(\d{1,2})\s*$', cmd)): my = get_my(leaf.reg.v.group(2))
        elif leaf.reg(re.match('(p|pay)\s*(\d{1,2})\s+(\d{1,3})\s*$', cmd)): # 136
            with dbm.open(db) as d:
                pld = ecc.i2b(int(leaf.reg.v.group(3)), 4)
                req = gene(bmy, ecc.h2b(get_my(leaf.reg.v.group(2))), pld, d)
        elif leaf.reg(re.match('(c|crt|cert)\s*(\d{1,2})\s*$', cmd)): # len:142
            with dbm.open(db) as d:
                req = gene(bmy, ecc.h2b(get_my(leaf.reg.v.group(2))), ecc.z10, d)
        elif re.match('(m|my)\s*$',                 cmd):
            with dbm.open(db) as d:
                for x in d.keys(): print (ecc.b2h(x).decode('UTF-8'))
            req = b''
        elif re.match('(q|quit)\s*$',               cmd):
            s.close()
            break
        if req:
            s.sendto(req, (ip, PORT1))
            data, addr = s.recvfrom(2048)
            if data:
                print (data.decode('UTF-8'))
                if   req == b'l':
                    with open('lpub',  'w') as f: f.write(data.decode('UTF-8'))
                elif req == bmy:
                    with open('proof', 'w') as f: f.write(data.decode('UTF-8'))

def start_access():
    ""
    t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    with open('proof') as f: pr = f.read()
    t.sendto(pr.encode('UTF-8'), (leaf.ip(), PORT2))
    data, addr = t.recvfrom(2048)
    if data: print (data.decode('UTF-8'))

def stop_access():
    ""
    t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    t.sendto(b'stop', (leaf.ip(), PORT2))
    data, addr = t.recvfrom(2048)
    if data: print (data.decode('UTF-8'))
        
def object(db, ip):
    ""
    k, t = ecc.ecdsa(), socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print ('Intelligent Object (socket open)')
    with dbm.open(db, 'c') as d:
        if len(d.keys()) == 0:
            k.generate()
            sk, pk = ecc.i2b(k.privkey, 48), k.compress(k.pt)
            d[b'KEYS'] = pk + sk
    t.bind((ip, PORT2))
    while True:
        (data, addr) = t.recvfrom(1024)
        with open('server_pk') as f: pk = f.read()
        k.pt = k.uncompress(ecc.z85decode(pk.encode('UTF-8')))
        if len(data)>130:
            sig, msg = ecc.z85decode(data[:120]), data[120:]
            if k.verify(sig, msg):
                cod = random.randrange(10000)
                t.sendto(b'start counting (code:%04d)' % cod, addr)
                dat = time.time()
            else:
                t.sendto(b'error on signature', addr)
        elif len(data) == 4:
            with dbm.open(db, 'c') as d:
                print (' %d secondes' % int(time.time()-dat))
                pk, sk = d[b'KEYS'][:48], d[b'KEYS'][48:]
                k.pt, k.privkey = k.uncompress(pk), ecc.b2i(sk)
                msg = b'invoice for %d secondes' % int(time.time()-dat)
                cmd =  ecc.z85encode(k.sign(msg)) + msg
                t.sendto(cmd, addr)
        else:
            t.sendto(b'error', addr)
        
if __name__ == "__main__":
    if   len(sys.argv) == 3:
        object('mem', sys.argv[2])
    elif len(sys.argv) == 2:
        phone('local', sys.argv[1], False)
    else:
        server('base', leaf.ip())
    
# end
