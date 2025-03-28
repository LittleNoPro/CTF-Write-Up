s = "75}9cbd89gv_f_ldetbmlrc8{FsCoTipc"
text = ""
for i in range(0, len(s), 3):
    text += s[i + 2]
    text += s[i]
    text += s[i + 1]
    # s[i], s[i + 1], s[i + 2] = s[i + 2], s[i], s[i + 1]

text = text[::-1]
print(text)