"""
Kek Security(aka Freakout, Necro) new DGA
references:
https://research.checkpoint.com/2021/freakout-leveraging-newest-vulnerabilities-for-creating-a-botnet/
https://blog.netlab.360.com/necro/

related specimens:
d65e874b247dda9845661734d9e74b921f700983fd46c3626a3197f08a3006bf
"""


import random

counter_=0

while 1:    
    if counter_>=0xFF:
        break        
    counter_ +=1


    random.seed(a=0x7228827A + counter_)

    dgadomain_=(''.join(random.choice("abcdefghijklmnopqoasadihcouvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(random.randrange(8,19)))).lower()       
    dgadomain_+="."+random.choice(["ddns.net","ddnsking.com","3utilities.com","bounceme.net",
                                   "freedynamicdns.net","freedynamicdns.org","gotdns.ch","hopto.org",
                                   "myddns.me","myftp.biz","myftp.org","myvnc.com","onthewifi.com",
                                   "redirectme.net","servebeer.com","serveblog.net","servecounterstrike.com",
                                   "serveftp.com","servegame.com","servehalflife.com","servehttp.com",
                                   "serveirc.com","serveminecraft.net","servemp3.com","servepics.com",
                                   "servequake.com","sytes.net","viewdns.net","webhop.me","zapto.org"])
    print(dgadomain_)

