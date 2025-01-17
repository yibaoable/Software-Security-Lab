for four in range(0, 0xFFFF):

    input_num = [0xc720, 0x0000, 0x0013, four]  # 改成你的三个序列号

    a = (input_num[1] - (input_num[3] & 0xF00)) & 0xF00

    b = (input_num[0] + input_num[1] + input_num[2] + input_num[3]) & 0xF

    c = (input_num[0] + (input_num[3] & 0xF000)) & 0xF000

    d = ( ( (input_num[2] ^ input_num[3]) & 0xF0) + a + b + c) ^ 0xAFDA

    if d == (input_num[0] + input_num[1] + input_num[2]) >> 4:
        print(hex(four))
        break