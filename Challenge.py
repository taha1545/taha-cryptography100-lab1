# i install pwntools

from pwn import *
import json, base64, codecs

def decode_payload(t, value):
    if t == "base64":
        return base64.b64decode(value).decode()
    elif t == "hex":
        return bytes.fromhex(value).decode()
    elif t == "rot13":
        return codecs.decode(value, "rot_13")
    elif t == "bigint":
        v = value[2:] if value.startswith("0x") else value
        if not v: return ""
        n = int(v,16)
        return n.to_bytes((n.bit_length()+7)//8, 'big').decode()
    elif t == "utf-8":
        return ''.join(chr(x) for x in value)
    else:
        raise ValueError("Unknown type")

r = remote('socket.cryptohack.org', 13377)
while True:
    data = json.loads(r.recvline().decode())
    if "flag" in data:
        print("FLAG:", data["flag"])
        break
    t = data["type"]
    enc = data["encoded"]
    dec = decode_payload(t, enc)
    r.sendline(json.dumps({"decoded": dec}).encode())
    
#  #result i got in terminal ::

#  PS C:\Users\DELL\Desktop> python .\solve_13377.py
# Connecting to socket.cryptohack.org:13377 ...
# [000] Type: utf-8 | Encoded: [99, 104, 97, 114, 105, 116, 121, 95, 108, 97, 98, 115, 95, 101, 110, 116, 101, 114, 112, 114, 105, 115, 101]
# [001] Type: hex | Encoded: 6f70696e696f6e5f706861726d61636f6c6f67795f636f6d6d
# [002] Type: bigint | Encoded: 0x666c6f6f72735f636f736d65746963735f726963686d6f6e64
# [003] Type: rot13 | Encoded: guebhtu_fnq_enqvbf
# [004] Type: utf-8 | Encoded: [98, 117, 108, 108, 101, 116, 95, 116, 117, 108, 115, 97, 95, 102, 97, 118, 111, 114, 105, 116, 101]
# [005] Type: hex | Encoded: 6a705f6465706f7369745f7368697274
# [006] Type: rot13 | Encoded: fnyg_rntyrf_ivqf
# [007] Type: base64 | Encoded: d29ybGRzX3ZlaGljbGVzX3JlcG9ydA==
# [008] Type: hex | Encoded: 766f69645f647572696e675f7265636f726473
# [009] Type: base64 | Encoded: d2lsZGxpZmVfdHJlYXRtZW50c19zdHVkaW8=
# [010] Type: utf-8 | Encoded: [98, 101, 110, 122, 95, 117, 110, 105, 116, 115, 95, 115, 105, 116, 117, 97, 116, 101, 100]
# [011] Type: bigint | Encoded: 0x61776172656e6573735f6761736f6c696e655f70757474696e67
# [012] Type: rot13 | Encoded: cebwrpgvba_xrab_unmneq
# [013] Type: utf-8 | Encoded: [111, 114, 100, 101, 114, 95, 99, 104, 105, 99, 107, 95, 109, 105, 115, 115, 105, 111, 110, 115]
# [014] Type: bigint | Encoded: 0x72656c69616e63655f77686963685f6f6674656e
# [015] Type: base64 | Encoded: cGVyY2VudGFnZV9vcGVuZWRfaGFyZGVy
# [016] Type: rot13 | Encoded: ybpnyr_orarsvgf_fbhgurea
# [017] Type: bigint | Encoded: 0x68615f6564656e5f6164616d
# [018] Type: bigint | Encoded: 0x6d61726b65645f7265616374696f6e5f6e657773
# [019] Type: hex | Encoded: 6d657965725f676f72646f6e5f766572697a6f6e
# [020] Type: hex | Encoded: 6d6f746f726f6c615f76616363696e655f706861726d61636575746963616c
# [021] Type: hex | Encoded: 6173736f63696174655f737572665f636f696e73
# [022] Type: rot13 | Encoded: cbq_guva_gz
# [023] Type: base64 | Encoded: ZXhwaXJlc19lcHNvbl9jYXNo
# [024] Type: utf-8 | Encoded: [109, 97, 110, 117, 97, 108, 95, 104, 105, 114, 105, 110, 103, 95, 99, 97, 116, 99, 104]
# [025] Type: base64 | Encoded: Y2hyaXN0bWFzX29tZWdhX3RpZXI=
# [026] Type: bigint | Encoded: 0x72656d69785f676c6f7665735f656d6d61
# [027] Type: base64 | Encoded: bWF4aW1pemVfYmxhbmtfdmVyeQ==
# [028] Type: bigint | Encoded: 0x74726164656d61726b5f636f6d6d697373696f6e65725f7061636b61676573
# [029] Type: base64 | Encoded: d2lkZXJfbHRkX3Jo
# [030] Type: utf-8 | Encoded: [104, 105, 116, 116, 105, 110, 103, 95, 112, 114, 111, 99, 101, 101, 100, 95, 101, 110, 97, 98, 108, 101, 100]
# [031] Type: rot13 | Encoded: onguebbz_ohefg_abgvba
# [032] Type: bigint | Encoded: 0x757365726e616d655f73635f656c6563746f72616c
# [033] Type: hex | Encoded: 686f6e65795f6d61696e7461696e735f776f7272696564
# [034] Type: base64 | Encoded: ZGtfbGlxdWlkX2NvcnBvcmF0aW9ucw==
# [035] Type: bigint | Encoded: 0x7469636b65745f6e657473636170655f73616964
# [036] Type: bigint | Encoded: 0x6d61726b6574706c6163655f61756374696f6e735f6672617564
# [037] Type: rot13 | Encoded: urnq_rkcnafvba_svkrf
# [038] Type: base64 | Encoded: Y2F0aGVyaW5lX2xlYXJuaW5nX2plcnNleQ==
# [039] Type: bigint | Encoded: 0x726573656172636865725f6361706162696c6974795f73686f6f74
# [040] Type: bigint | Encoded: 0x6f66666572696e67735f74726561737572655f63757465
# [041] Type: base64 | Encoded: YWNxdWlzaXRpb25fcGFydGljaXBhbnRfdHJhZGl0aW9uYWw=
# [042] Type: hex | Encoded: 6e61727261746976655f766563746f725f6d69646c616e6473
# [043] Type: hex | Encoded: 666f6f5f636f6e73756c745f746f6f6b
# [044] Type: utf-8 | Encoded: [122, 111, 111, 109, 95, 100, 101, 112, 101, 110, 100, 115, 95, 97, 116, 101]
# [045] Type: utf-8 | Encoded: [114, 111, 112, 101, 95, 99, 108, 97, 117, 115, 101, 95, 100, 101, 99, 111, 114, 97, 116, 105, 118, 101]
# [046] Type: base64 | Encoded: cGlja2VkX2Ryb3BwZWRfYmV0dHk=
# [047] Type: base64 | Encoded: Ym9vdGhfYnVmX3N0cnVjaw==
# [048] Type: utf-8 | Encoded: [105, 110, 116, 101, 114, 105, 109, 95, 116, 97, 108, 107, 115, 95, 100, 99]
# [049] Type: hex | Encoded: 6475746965735f6c6567656e646172795f726f67657273
# [050] Type: hex | Encoded: 696e6772656469656e74735f656c656d656e745f6f6666656e73697665
# [051] Type: base64 | Encoded: YnJpZWZpbmdfcmFua2luZ19vdXRjb21l
# [052] Type: bigint | Encoded: 0x7a755f6573636f7274735f6273
# [053] Type: hex | Encoded: 6869657261726368795f6f6c6976655f726577617264
# [054] Type: hex | Encoded: 626f6f6b6d61726b5f7472656d656e646f75735f73697474696e67
# [055] Type: utf-8 | Encoded: [100, 101, 102, 101, 110, 115, 101, 95, 110, 111, 100, 101, 115, 95, 99, 111, 108, 111, 117, 114, 115]
# [056] Type: bigint | Encoded: 0x6f7a5f65786368616e6765735f7375676765737473
# [057] Type: rot13 | Encoded: cnegf_jnxr_cbylrfgre
# [058] Type: base64 | Encoded: YWR2YW50YWdlc19mYXN0ZXJfc2hhbm5vbg==
# [059] Type: base64 | Encoded: cmVhc29uX3RyaWJ1dGVfc2s=
# [060] Type: hex | Encoded: 737563636565645f776f6f645f72697065
# [061] Type: base64 | Encoded: Y2hvaXJfcG9zaXRpb25pbmdfYWY=
# [062] Type: rot13 | Encoded: gunax_rqvgbevny_whyvr
# [063] Type: hex | Encoded: 6775696c74795f6166666563745f6e65656473
# [064] Type: bigint | Encoded: 0x6465656d65645f7363686f6c6172735f746f70696373
# [065] Type: rot13 | Encoded: cerfvqrag_zrgnobyvfz_ulqebtra
# [066] Type: bigint | Encoded: 0x636c696e6963616c5f696e7465727072657465645f6465706f73697473
# [067] Type: hex | Encoded: 6675726e69747572655f6775657374626f6f6b5f61697266617265
# [068] Type: utf-8 | Encoded: [99, 99, 95, 97, 108, 109, 111, 115, 116, 95, 109, 105, 110, 117, 115]
# [069] Type: bigint | Encoded: 0x6f7267616e697a65645f76656c7665745f656666696369656e74
# [070] Type: bigint | Encoded: 0x74696d65735f626f6f6d5f657870
# [071] Type: rot13 | Encoded: pbairavrapr_tenqhngvba_pbz
# [072] Type: utf-8 | Encoded: [112, 111, 115, 115, 101, 115, 115, 105, 111, 110, 95, 112, 101, 114, 102, 111, 114, 109, 97, 110, 99, 101, 115, 95, 112, 97, 114, 116, 110, 101, 114, 115, 104, 105, 112, 115]
# [073] Type: base64 | Encoded: c2V0dGxlZF9wcmVzY3JpYmVkX21l
# [074] Type: bigint | Encoded: 0x616e615f636f6d70696c6174696f6e5f7475726b697368
# [075] Type: bigint | Encoded: 0x636f6d70617261746976655f6c6177735f737472696b65
# [076] Type: rot13 | Encoded: pbhagrq_sbyqre_yrnq
# [077] Type: base64 | Encoded: cGlhbm9fdGVybWlub2xvZ3lfZnVqaQ==
# [078] Type: hex | Encoded: 65615f736f6e735f76616c756174696f6e
# [079] Type: hex | Encoded: 7461626c655f6170706561725f686f72726f72
# [080] Type: rot13 | Encoded: vqragvgl_qvfnoyrq_cenpgvprf
# [081] Type: hex | Encoded: 6a616d5f6f706572617465645f6d6f62696c6573
# [082] Type: utf-8 | Encoded: [109, 101, 114, 103, 101, 95, 115, 99, 114, 101, 101, 110, 115, 104, 111, 116, 115, 95, 112, 114, 105, 100, 101]
# [083] Type: utf-8 | Encoded: [100, 105, 115, 116, 114, 105, 99, 116, 95, 114, 101, 116, 117, 114, 110, 105, 110, 103, 95, 118, 97, 108, 118, 101]
# [084] Type: base64 | Encoded: ZGpfcmVsaWdpb25zX2V0aGljcw==
# [085] Type: base64 | Encoded: Z3VpZGVfcHJpbmNlX2xlZQ==
# [086] Type: base64 | Encoded: dGltZV9oYW5kaGVsZF9tZW1icmFuZQ==
# [087] Type: hex | Encoded: 62616c74696d6f72655f6d6174685f686f77746f
# [088] Type: base64 | Encoded: c21pdGhfbmF0aW9uX21pcmFjbGU=
# [089] Type: base64 | Encoded: b2JzZXJ2YXRpb25zX2FycmF5X251
# [090] Type: base64 | Encoded: Y2FyYm9uX2NvbGxlYWd1ZV9tc2dpZA==
# [091] Type: utf-8 | Encoded: [116, 101, 114, 109, 105, 110, 97, 108, 95, 110, 97, 115, 104, 118, 105, 108, 108, 101, 95, 100, 105, 103, 105, 116, 97, 108]
# [092] Type: bigint | Encoded: 0x76655f756e6974795f657175616c6c79
# [093] Type: base64 | Encoded: dHN1bmFtaV9qZXJzZXlfdGFicw==
# [094] Type: hex | Encoded: 6472756e6b5f6d61746368696e675f696e636f72706f7261746564
# [095] Type: utf-8 | Encoded: [116, 105, 103, 104, 116, 95, 99, 97, 109, 101, 114, 97, 115, 95, 110, 101, 118, 101, 114, 116, 104, 101, 108, 101, 115, 115]
# [096] Type: utf-8 | Encoded: [100, 97, 118, 105, 100, 95, 102, 105, 108, 108, 101, 100, 95, 99, 104, 101, 97, 112, 101, 114]
# [097] Type: base64 | Encoded: Y29tbW9uc19kaXNjdXNzaW5nX2RldGVybWluYXRpb24=
# [098] Type: rot13 | Encoded: ohs_vef_pof
# [099] Type: utf-8 | Encoded: [100, 105, 118, 101, 114, 115, 101, 95, 97, 117, 116, 104, 101, 110, 116, 105, 99, 95, 99, 101, 108, 108, 117, 108, 97, 114]

# === FLAG ===
# crypto{3nc0d3_d3c0d3_3nc0d3}
# ============
# PS C:\Users\DELL\Desktop>    
