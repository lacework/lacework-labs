"""
Muhstik UPX patcher

Description:
Replaces Muhstik's custom UPX header with valid header so file
can be unpacked

Instructions:
Place files in directory and update the input_folder name

related specimens:
b3a6fe5bc3883fd26c682bb6271a700b8a6fe006ad8df6c09cc87530fcd3a778
2a4e636c4077b493868ea696db3be864126d1066cdc95131f522a4c9f5fb3fec
c38f0f809a1d8c50aafc2f13185df1441345f83f6eb4ef9c48270b9bd90c6799
6370939d4ff51b934b7a2674ee7307ed06111ab3b896a8847d16107558f58e5b
a3f72a73e146834b43dab8833e0a9cfee6d08843a4c23fdf425295e53517afce
b55ddbaee7abf1c73570d6543dd108df0580b08f730de299579570c23b3078c0
6a8965a0f897539cc06fefe65d1a4c5fa450d002d1a9d5d69d2b48f697ee5c05
e20806791aeae93ec120e728f892a8850f624ce2052205ddb3f104bbbfae7f80
63d43e5b292b806e857470e53412310ad7103432ba3390ecd4f74e432530a8a9
715f1f821d028e165bfa750d73505f1a6136184999411300cc88c18ebfa6e8f7
c154d739cab62e958944bb4ac5ebad6e965a0442a3f1c1d99d56137e3efa8e40
19370ef36f43904a57a667839727c09c50d5e94df43b9cfb3183ba766c4eae3d


"""

import os

custom_upx_header = '0a000000'#Muhstik UPX header
upx = '55505821'#UPX!

input_folder = "input_folder"#update with your directory name


files_ = os.listdir(input_folder)

print('patching ',len(files_),'files')




def patch(to_hex_temp,custom_upx_header,upx):

    if len(to_hex_temp) < 4:
        return         

    if len(to_hex_temp) > 4:

        body_temp = to_hex_temp[1:-2]

        body = custom_upx_header.join(body_temp)

        to_hex_patched = to_hex_temp[0]+upx+body+upx+to_hex_temp[-2]+upx+to_hex_temp[-1]

    else:
        to_hex_patched = upx.join(to_hex_temp)
    

    return to_hex_patched


for input_file in files_:
    input_ = input_folder+input_file


    output_ = 'patched_'+input_file

    with open(input_,'rb') as f_:
        data = f_.read()

        to_hex = str(data.encode("hex"))

    f_.close()


    to_hex_temp = to_hex.split(custom_upx_header)

    to_hex_patched = patch(to_hex_temp,custom_upx_header,upx)

    if to_hex_patched is None:
        print(input_file,' either not Muhstik UPX or different header')
        continue

    with open(output_,'wb') as f_out:
        patched_object = to_hex_patched.decode('hex')
        f_out.write(patched_object)

    f_out.close()
    print('wrote patched file as ',output_)



