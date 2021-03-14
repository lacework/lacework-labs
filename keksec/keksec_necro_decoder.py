"""
Necro python decoder (aka Kek Security & Freakout))

references:
https://research.checkpoint.com/2021/freakout-leveraging-newest-vulnerabilities-for-creating-a-botnet/
https://blog.netlab.360.com/necro/

related specimens:
0688803466715567a1701a7b8fec82eb2fd777012207bfc6420283ec9b2accd4
0e600095a3c955310d27c08f98a012720caff698fe24303d7e0dcb4c5e766322
2059188320fce363aa51d869179fe31438c75630b28113c788816cd2ebf5cc73
2100597ade13d5dd214e0ec746d9a1ae6583a701d5ae186ff75e80d9287b925c
2c79e494da51704f252d868a585fd5a776766298215c31f51e89b7a73a8cd0a4
30df8863ad55b7cec836505e9c14f94564a5a71622839ff98a9af0d613d6a694
3379fd14b787276d260be06afb3ec7239c8b5e475eb2905a9374357cce15561a
3bb43b360ec05797cfdcb2e07d5113f86dc542fbc51e983708894376978558f0
48fc303cf71049ef0751404e5050c1caf7c107e6498fc47c81151e3876820779
5dbfb9f305cbc5ed624d8b976835aac33b161c0e290da6338cc56ed409a26029
622574858ad5dbb7a34479f38f90709e4595d89b1e1d807078dab125d566a2f1
664da61b3fada70c49e3a05f119920f442f305f809dd1964038899c57a7f7871
7074a9e8fe2c629d9a799ab0ae7b48717aeb57a56dd9c7c6ac707d7ab46b39b4
81ac7b096c0d9c5411e54cf88b779d85280444452452e50ca1f14a096e6ff909
867f640bccd190c247de5b8fe02cc09ff6e1ba6f639a832ba78b10a93ca2c174
8ee3eb6f7b0ea9801a34f2077b083e85d35bb5884423dc80efab072034d27211
99e959128d3e1fbfbec03f8f6b9f8587e18673842a238bfb9aa981cc759d0fd9
9ded00d35a7a4c5e5b29c34c3fdfd8d829f642b87a378a65aca1d51f231366a7
a4e4353ce189c5cb9970dc1bd281e54db229d05f0c435adc1f6e585cd3ca5d23
ad948c35894223e2ec74c9474a417c581d51ec29484bbf6121b861ee9ae20b94
c4df5348c604ad9d1c789a692d6a2c483e05b3d1a114c4e67960677a4103da33
e3bb8207e62656154139b37dc731101234155fe9279d5fb4a0b1c70ed98c4220
e5963be25dcf11c41914084e769a9361aa06adf726091b6638effd4a652b5de7
fc409d581c5b4cdf595e6d3027dfb8d2a72ade069c1f7b6e35b9c2f081e5fb90
1a3b4f3a06d4d62ac16a897c310667ac6915ce66d07acd0ebf877101bc125ad3
2138d18a978342f9e6b0ed985aaeffcaa88878d0d5c0ae1bfe06131a390732e6
29ecb616722937cb6a1490c83dbc7d59e2991a4378e4d4c3553da498d04773e9
5d3ab350ca322f0a5ccdfcf70be6497b05d15589819b60aa477646070ceef398
5d8dbdd7bf9e8197b88806bbc30395e0d844c01bc0646682cc65676131338f31
6c942e9a0522ccc17732e2771c1cd2a09bb6471e01f63b08b4c7aed56ff3ac88
8609c3aab7a8ef7cce7ec2afe577c939c3824564bfc0400062cbb1084d085ec9
b5f8a64e7a08402bce74fe70c9d29652f7afdd64c25952cc6cb333ef980dc272
da881e245e9dc5e796dc3b29a1c9ddadae669d1c3ac059708ee68bb91f8dce70
f3338d7fc288dff92e94a69e0f4c663170b74d5b64148fd212b8dff504214d7a
f34b35fef16a1565e4f04cdb695c7a63c88d380daefa53e9833b17f2b06ac8a8

"""




import zlib
import ast
import re
import os
import sys

print('finding cipher func..')

def getconfig(obfuscated_py):
    with open(obfuscated_py) as infile:
        iterator = 0
        for line in infile:
            if line.startswith("def "):
                iterator += 1            
                funcname = line.split("def ")[1].split("(s)")[0]

            try:
                if iterator == 1:
                    if "=" in line:
                        key_ = line.split("=")[1].strip()
                        key_ = key_.lstrip().rstrip()

                        if type(ast.literal_eval(key_)) == list:
                            keyarray = ast.literal_eval(key_)
                            print('found key',keyarray)
                            return funcname,keyarray
            except:
                pass
                

def dekodfunc(s,keyarray):
    array_ = keyarray
    return ''.join([chr(ord(c) ^array_[i % len(array_)]) for i, c in enumerate(s)])




def deobfuscate_(obfuscated_py,deobfuscated_py):

    configs = getconfig(obfuscated_py)



    func_name = configs[0]
    keyarray = configs[1]


    with open(deobfuscated_py,'w') as f_:

        with open(obfuscated_py,'r') as infile:
            for line in infile:

                iterationcount = 0

                while True:
                    if func_name in line:

                        iterationcount += 1
                        try:
                            sig = func_name+"(zlib.decompress("
                            before_ = line.split(sig)[0]
                            after_ = line.split(sig)[1].split("))")[1]
                            
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

