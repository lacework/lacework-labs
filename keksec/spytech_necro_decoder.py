"""
"Spytech Necro" python decoder

references:
https://www.lacework.com/blog/keksec-tsunami-ryuk/
https://www.lacework.com/blog/the-kek-security-network/


related specimens:

60da4b3da2ba3309c473643df4a6782ecb6388974c31f0e6afb68bef6b240a2e
afd7c59bf18d1eb628b1afe5d24ae3cfeb759d782dde89e46430ae6371a67f71
e596592ce9b8a8652864f9a4d330729353157351e17fcc66fe5c3af2258ffc04
0893ccc28379e75aca8b75482d779a8e20af75af0d3fbf21bc861915d0e77669
ddce94c4f3cb522c074c7272f605e54a22c1e189eec647ec6e88f87bc4cdd8da
e524bd7789b82df11891cc2c12af1ac0ea41dd0b946e1e04a4246cb36321f82f
df81f1bf0e7fd182a777044b1a9e25b9aae9a6e9a4b490c8631177cac6312362
"""




import zlib
import ast
import re
import os
import sys



keyarray = '\x65hhhhFuckSpyTechUsersWeDaMilitiaAnonym00se'


def getfunc(obfuscated_py):

    with open(obfuscated_py) as infile:
        iterator = 0
        for line in infile:
            if line.startswith("def "):
                iterator += 1            
                funcname = line.split("def ")[1].split("(s)")[0]
                break

    return funcname
                



def dekodfunc(s,keyarray):
    array_ = keyarray
    return ''.join([chr(ord(c) ^ ord(array_[i % len(array_)])) for i, c in enumerate(s)])



def deobfuscate_(obfuscated_py,deobfuscated_py):

    func_name = getfunc(obfuscated_py)



    with open(deobfuscated_py,'w') as f_:

        with open(obfuscated_py,'r') as infile:
            for line in infile:

                iterationcount = 0

                while True:
                    if func_name in line:

                        iterationcount += 1
                        try:
                            sig = func_name+"(zlib.decompress("
                            
                            temp = line.split(sig)[1].split("))")[0]
                            tempnew = ast.literal_eval(temp)
                            dekoded = '"'+dekodfunc(zlib.decompress(tempnew),keyarray)+'"'

                            originalstr = func_name+"(zlib.decompress("+temp+"))"
                            
                            if '\n' in dekoded or '\r' in dekoded :
                                dekoded = dekoded.replace("\n", " ")
                                dekoded = dekoded.replace("\r", " ")
                                dekoded = dekoded.replace("\t", " ")

                            newline = line.replace(originalstr,dekoded)

                            line = newline

                            if func_name not in line:
                                f_.write(line)
                                break
                            
                        except Exception, e:                       
                            f_.write(line)                 
                            break
                    else:

                        f_.write(line)
                        break


           
if __name__ == '__main__':

    errors = 0

    if len(sys.argv) == 2:

        obfuscated_py = sys.argv[1]
        deobfuscated_py = obfuscated_py+'_decoded.py'

        deobfuscate_(obfuscated_py,deobfuscated_py)
        print('wrote decoded file to ',deobfuscated_py)
       
    else:
        print("Needs argument!")
        print("usage - keksec_necro_decoder.py [obfuscated py malware]")
        exit(1)
