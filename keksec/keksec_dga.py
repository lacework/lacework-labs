"""
Kek Security(aka Freakout, Necro) new DGA

references:
https://research.checkpoint.com/2021/freakout-leveraging-newest-vulnerabilities-for-creating-a-botnet/
https://blog.netlab.360.com/necro/


related specimens:
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


import random

counter_=0

while 1:    
    if counter_>=0xFF:
        break        
    counter_ +=1

    random.seed(a=0x7774DEAD + counter_)

    dgadomain_=(''.join(random.choice("abcdefghijklmnopqoasadihcouvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(random.randrange(10,19)))).lower()       
    dgadomain_+="."+random.choice(["ddns.net","ddnsking.com","3utilities.com","bounceme.net",
                                   "freedynamicdns.net","freedynamicdns.org","gotdns.ch","hopto.org",
                                   "myddns.me","myftp.biz","myftp.org","myvnc.com","onthewifi.com",
                                   "redirectme.net","servebeer.com","serveblog.net","servecounterstrike.com",
                                   "serveftp.com","servegame.com","servehalflife.com","servehttp.com",
                                   "serveirc.com","serveminecraft.net","servemp3.com","servepics.com",
                                   "servequake.com","sytes.net","viewdns.net","webhop.me","zapto.org"])
    print(dgadomain_)




        
