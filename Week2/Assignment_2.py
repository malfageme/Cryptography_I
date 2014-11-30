#!/usr/bin/python

from Crypto.Cipher import AES
from Crypto.Util import Counter

questions = []
questions.append ( {'mode': 'CBC', 'key':'140b41b22a29beb4061bda66b6747e14','msg':'4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81'} )
questions.append ( {'mode': 'CBC', 'key':'140b41b22a29beb4061bda66b6747e14','msg':'5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253'} )
questions.append ( {'mode': 'CTR', 'key':'36f18357be4dbd77f050515c73fcf9f2','msg':'69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329'} )
questions.append ( {'mode': 'CTR', 'key':'36f18357be4dbd77f050515c73fcf9f2','msg':'770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451'} )

for i in range(len(questions)):
    print "==========================================="
    print "Question %d - %s" % (i, questions[i]['mode'])
    print "  key= %s" % questions[i]['key']
    print "  msg= %s" % questions[i]['msg']

    mode = questions[i]['mode']
    key = questions[i]['key'].decode('hex')
    msg = questions[i]['msg'].decode('hex')

    if mode == 'CBC':
        mode = AES.MODE_CBC
        obj = AES.new(key, mode, msg[:16])
        print obj.decrypt (msg[16:])
    elif mode == 'CTR':
        mode = AES.MODE_CTR
        iv=int(questions[i]['msg'][:32],16)
        print "CTR IV: %d  - " % iv, iv
        ctr = Counter.new(nbits=128, initial_value=iv)
        obj = AES.new(key, mode, '', ctr)
        print obj.decrypt (msg[16:])


exit()


key = key_hex.decode('hex')

m1 = "attack at dawn"
m2 = "attack at dusk"
m1_hex = map(hex, map(ord, m1))
m1_int = map(ord, m1)
m2_int = map(ord, m2)

c1_str = "09e1c5f70a65ac519458e7e53f36"


def convert_from_base_str_to_num(hex_str, base):
    res = []
    i = 0
    j = 2
    l = len(hex_str)
    while j <= l:
        #print 'Hex_str[%d,%d]=%s' % (i,j,hex_str[i:j])
        res.append(int(hex_str[i:j], base))
        i += 2
        j += 2
    return res



def convert_from_base_str_to_char(hex_str, base):
    res = []
    i = 0
    j = 2
    l = len(hex_str)
    while j <= l:
        #print 'Hex_str[%d,%d]=%s' % (i,j,hex_str[i:j])
        res.append(chr(int(hex_str[i:j], base)))
        i += 2
        j += 2
    return res

def apply_xor (m,c):
    if len(m) != len(c):
        exception('Error: strings length not equal')
    res = [] 
    i = 0
    l = len(m)
    while i < l:
        res.append(m[i] ^ c[i])
        i += 1
    return res


def strxor(a, b):
    if len(a) > len(b):
        return "".join( [chr(ord(x) ^ ord(y)) for (x,y) in zip(a[:len(b)],b)] )
    else:
        return "".join( [chr(ord(x) ^ ord(y)) for (x,y) in zip(a,b[:len(a)])] )
       
 
c1_int = convert_from_base_str_to_num(c1_str, 16)
k_int = apply_xor(m1_int, c1_int)
c2_int = apply_xor(m2_int, k_int)

#print "Message 1:",m1
#print "Message 1(hex):",m1_hex
#print "Message 1(hex_enc):", m1.encode('hex')
#print "Message 1(int):", m1_int
#print "Cypher message 1 (hex_str):", c1_str
#print "Cypher message 1 (int):", c1_int
#print "Cypher message 1 (char):", convert_from_base_str_to_char(c1_str, 16)
#print "Cypher message 1 (hex):",''.join(map("{0:02x}".format, c1_int))
#print "Key (int):",k_int
#print "Key (str):",map(chr,k_int)
#print "Message 2:",m2
#print "Message 2 (int):",m2_int
#print "Message 2 (hex):",map(hex, m2_int)
#print "Message 2 (hex):",' '.join(map(hex, m2_int)).replace('0x','')
#print "Message 2 (hex):",''.join(map("{0:02x}".format, m2_int))
#
#print "Cypher Message 2:",c2
#print "Cypher Message 2 (int):",c2_int
#print "Cypher Message 2 (hex):",map(hex, c2_int)
#print "Cypher Message 2 (hex):",' '.join(map(hex, c2_int)).replace('0x','')
#print "Cypher Message 2 (hex):",''.join(map("{0:02x}".format, c2_int))


def isascii(c):
    if (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z'):
        return True
    return False


def format_ascii(msg, key):
    res = ''
    for i in range(len(msg)):
        #print "isascii(msg[%d])=%s , key[%d]=%s" % (i, isascii(msg[i]), i, key[i])
        if isascii(msg[i]) and (ord(key[i]) != 0):
            res += msg[i]
            #if key[i] != 0:
            #    res += msg[i]
        else:
            res += '_'
    return res


print "Message 1:",m1
k = strxor(m1,c1_str.decode('hex'))
print "Key:",k
print "Key (hex):",k.encode('hex')
print "Message 2:", m2
c2 = strxor(m2, k)
print "Message 2 (encoded):", c2
print "Message 2 (encoded) (hex):", c2.encode('hex')


c_msg = []
for c in c_hex:
    print c
    c_msg.append(c.decode('hex'))

print c_msg

tc = tc_hex.decode('hex')

msg_plain2 = []

for msg_base in range(len(c_msg)):

    print "Searching blank spaces for msg", msg_base
    cypher_msg1 = c_msg[msg_base]
    blanks = {}
    msg_plain_base = ''
    for c in range(len(cypher_msg1)):
        msg_plain_base += ' '


    for msg_id in range (len(c_msg)):
        if msg_id == msg_base:
            cypher_msg2 = tc
        else:
            cypher_msg2 = c_msg[msg_id]
        #print "  Computing msg_id", msg_id
        msg_xor = strxor(cypher_msg1, cypher_msg2)
        i = 0
        l = len(msg_xor)
        while i < l:
            if isascii(msg_xor[i]):
                if i in blanks:
                    blanks[i] += 1
                else:
                    blanks[i] = 1
                if msg_xor[i].isupper():
                    msg_plain_base=msg_plain_base[:i]+msg_xor[i].lower()+msg_plain_base[i+1:]
                else:
                    msg_plain_base=msg_plain_base[:i]+msg_xor[i].upper()+msg_plain_base[i+1:]
            i += 1
        #print blanks
        print msg_plain_base

    msg_plain2.append(msg_plain_base)
    

    print "Blank spaces on positions:",
    max = 0
    for i in sorted(blanks, key=blanks.get, reverse=True):
        if blanks[i] < len(c_msg)-2:
            break
        else:
            max = blanks[i]
            print i,
            if ord(key[i]) == 0:
                key = key[:i]+str(chr(ord(cypher_msg1[i]) ^ ord(' ')))+key[i+1:]
            #print chr(ord(c_msg[0][i]) ^ ord(' '))
    print 
    print "Key:", key.encode('hex')

print "Key:", key.encode('hex')


# Decoding

print "    Messages decoded"
print "========================"

msg_plain = []
for c in c_msg:
    msg_plain.append(strxor(c,key))

for msg in msg_plain: 
    print format_ascii(msg,key)

print format_ascii(strxor(tc_hex.decode('hex'),key), key)

print format_ascii(msg_plain[7][:5], key)

for msg in msg_plain2: 
    print msg

#for c in c_msg:
#    print strxor(c,key).encode('hex')




