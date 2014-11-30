

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
        
c1_int = convert_from_base_str_to_num(c1_str, 16)
k_int = apply_xor(m1_int, c1_int)
c2_int = apply_xor(m2_int, k_int)

print "Message 1:",m1
print "Message 1(hex):",m1_hex
print "Message 1(int):", m1_int
print "Cypher message 1 (hex_str):", c1_str
print "Cypher message 1 (int):", c1_int
print "Cypher message 1 (char):", convert_from_base_str_to_char(c1_str, 16)
print "Cypher message 1 (hex):",''.join(map("{0:02x}".format, c1_int))
print "Key (int):",k_int
print "Key (str):",map(chr,k_int)
print "Message 2:",m2
print "Message 2 (int):",m2_int
print "Message 2 (hex):",map(hex, m2_int)
print "Message 2 (hex):",' '.join(map(hex, m2_int)).replace('0x','')
print "Message 2 (hex):",''.join(map("{0:02x}".format, m2_int))

#print "Cypher Message 2:",c2
print "Cypher Message 2 (int):",c2_int
print "Cypher Message 2 (hex):",map(hex, c2_int)
print "Cypher Message 2 (hex):",' '.join(map(hex, c2_int)).replace('0x','')
print "Cypher Message 2 (hex):",''.join(map("{0:02x}".format, c2_int))





