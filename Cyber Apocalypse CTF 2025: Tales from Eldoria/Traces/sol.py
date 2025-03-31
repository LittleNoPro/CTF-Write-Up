from pwn import *

def XOR(a, b):
    res = b""
    for i in range(min(len(a), len(b))):
        res += bytes([a[i] ^ b[i]])
    return res

io = remote("94.237.55.186", 51601)
# io.sendafter(b"> ", b"JOIN #general\n")

key = "%mi2gvHHCV5f_kcb=Z4vULqoYJ&oR"
io.sendafter(b"> ", b"JOIN #secret " + key.encode() + b'\n')
io.recvline()

ct = []
for _ in range(15):
    io.recvuntil(b"> : ")
    ct.append(io.recvline().strip().decode())


for i in range(len(ct)):
    ct[i] = bytes.fromhex(ct[i])

pt = b"!leave"
keystream = XOR(ct[14], pt)

for i in range(len(ct)):
    print(XOR(ct[i], keystream), i)




"""
Chat in #general

b'!nick Doomfang' 0
b'!nick Stormbane' 1
b'!nick Runeblight' 2
b"We've got a new tip about the rebels. Let's keep our chat private." 3
b'Understood. Has there been any sign of them regrouping since our last move?' 4
b"Not yet, but I'm checking some unusual signals. If they sense us, we might have to c" 5
b"This channel is not safe for long talks. Let's switch to our private room." 6
b'Here is the passphrase for our secure channel: %mi2gvHHCV5f_kcb=Z4vULqoYJ&oR' 7
b'Got it. Only share it with our most trusted allies.' 8
b'Yes. Our last move may have left traces. We must be very careful.' 9
b"I'm checking our logs to be sure no trace of our actions remains." 10
b"Keep me updated. If they catch on, we'll have to act fast." 11
b"I'll compare the latest data with our backup plan. We must erase any sign we were he" 12
b'If everything is clear, we move to the next stage. Our goal is within reach.' 13
b"Hold on. I'm seeing strange signals from outside. We might be watched." 14
b"We can't take any risks. Let's leave this channel before they track us." 15
b'Agreed. Move all talks to the private room. Runeblight, please clear the logs here.' 16
b"Understood. I'm disconnecting now. If they have seen us, we must disappear immediate" 17
b'!leave' 18
b'!leave' 19
b'!leave' 20
"""




"""
Chat in #secret

b'!nick Stormbane' 0
b'!nick Runeblight' 1
b'We should keep our planning here. The outer halls are not secure, and too many eyes watch the open channels.' 2
b"Agreed. The enemy's scouts grow more persistent. If they catch even a whisper of our designs, they will move against us. We must not allow their seers or spies to track our steps." 3
b"I've been studying the traces left behind by our previous incantations, and something feels wrong. Our network of spells has sent out signals to an unknown beacon-one that none of " 4
b"I'm already cross-checking our spellwork against the ancient records. If this beacon was part of an older enchantment, I'll find proof. But if it is active now, then we have a prob" 5
b"We cannot afford hesitation. If this is a breach, then the High Council's forces may already be on our trail. Even the smallest mistake could doom our entire campaign. We must conf" 6
b'Exactly. And even if we remain unseen for now, we need contingency plans. If the Council fortifies its magical barriers, we could lose access to their strongholds. Do we have a sec' 7
b'Yes, but we must treat it only as a last resort. If we activate it too soon, we risk revealing its location. It is labeled as: HTB{Crib_Dragging_Exploitation_With_Key_Nonce_Reuse!}' 8
b'Good. No record of it must exist in the written tomes. I will ensure all traces are erased, and it shall never be spoken of openly. If the enemy ever learns of it, we will have no ' 9
b'Agreed. The more we discuss it, the greater the risk. Every moment we delay, the Council strengthens its defenses. We must act soon before our window of opportunity closes.' 10
b'We should end this meeting and move to a more secure sanctum. If their mages or spies are closing in, they may intercept our words. We must not take that chance. Let this be the la' 11
b'!leave' 12
b'!leave' 13
b'!leave' 14
"""

# HTB{Crib_Dragging_Exploitation_With_Key_Nonce_Reuse!}