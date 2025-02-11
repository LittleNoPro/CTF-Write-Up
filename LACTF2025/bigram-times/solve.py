characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789{}~_"

def bigram_multiplicative_shift(bigram):
    assert(len(bigram) == 2)
    pos1 = characters.find(bigram[0]) + 1
    pos2 = characters.find(bigram[1]) + 1
    shift = (pos1 * pos2) % 67
    return characters[((pos1 * shift) % 67) - 1] + characters[((pos2 * shift) % 67) - 1]

not_the_flag = "mCtRNrPw_Ay9mytTR7ZpLJtrflqLS0BLpthi~2LgUY9cii7w"
also_not_the_flag = "PKRcu0l}D823P2R8c~H9DMc{NmxDF{hD3cB~i1Db}kpR77iU"

ct = "jlT84CKOAhxvdrPQWlWT6cEVD78z5QREBINSsU50FMhv662W"
pt = ""
for z in range(0, len(ct), 2):
    bigram = ct[z:z+2]

    for i in characters:
        for j in characters:
            if bigram_multiplicative_shift(i+j) == bigram:
                if i + j == not_the_flag[z:z+2] or i + j == also_not_the_flag[z:z+2]:
                    continue

                pt += i + j



print(pt)

# lactf{mULT1pl1cAtiV3_6R0uPz_4rE_9RE77y_5we3t~~~}