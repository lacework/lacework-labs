# -----------------------------------------------------------
# Generates Yara rule for detecting a given string in 
# obfuscated PHP files
#
# Released under GNU Public License (GPL)
# email christopher.hall@lacework.net
# -----------------------------------------------------------

from itertools import permutations
import itertools
import hashlib


mystring = 'stratum+tcp'#obfuscated string to search

rule_name = "stratum_obfuscated"#your Yara rule name

yara_rule_file = "stratum_obf_yara.txt"#your Yara rule file


f = open(yara_rule_file,"w")

f.write('rule '+rule_name+'\n')
f.write('{\n')
f.write('strings:\n')

S = []

S2 = []


for m in mystring:
    ord_ = ord(m)


    bytecode_hex = "\\x"+m.encode("hex")
    bytecode_octal = "\\"+str(int(oct(ord_)))


    S.append([m,bytecode_hex])
    S2.append([bytecode_octal,bytecode_hex])



seen = set()

a = set(["".join(x) for x in itertools.product(*S)])



kount = 0
for i in a:

    if i == mystring:
        continue
        
    kount += 1
    i = i.encode("hex")

    hash_object = hashlib.md5(i.encode())
    hash1 = (hash_object.hexdigest())
    yara_id = hash1[:10]

    if i not in seen:

        f.write('$string_'+yara_id+' = {'+str(i)+'}')
        f.write('\n')

    seen.add(i)



a = set(["".join(x) for x in itertools.product(*S2)])


kount = 0
for i in a:

    if i == mystring:
        continue
        

    kount += 1
    i = i.encode("hex")


    hash_object = hashlib.md5(i.encode())
    hash1 = (hash_object.hexdigest())
    yara_id = hash1[:10]

    if i not in seen:
        f.write('$string_'+yara_id+' = {'+str(i)+'}')
        f.write('\n')

    seen.add(i)




f.write('\n')

f.write('condition:\n')
f.write('\n')


f.write('any of ($s*)')
f.write('\n')

f.write('}\n')
f.write('\n')

f.close()


print('wrote Yara rule to '+yara_rule_file)
