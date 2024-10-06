import frida
import sys
import json
import struct
import requests

s = requests.Session()

DOMAIN = "10.1.242.236:6779"


def on_message(message, data):
    # print(message)
    try:
        j = json.loads(message["payload"])
        t = j["type"]

        if t == "tea_encrypt":
            o = {
                "mode": "tea",
                "enc": True,
                "data": j["data"],
                "result": j["result"],
                "key": j["key"],
            }
            s.post(f"http://{DOMAIN}/tea", data=json.dumps(o))

            try:
                b = bytes.fromhex(j["data"])

                headLen = struct.unpack("!i", b[:4])[0]
                seq = struct.unpack("!i", b[4:8])[0]
                appid = struct.unpack("!i", b[8:12])[0]
                localId = struct.unpack("!i", b[12:16])[0]
                # struct.unpack("!i!i!i", b[16:28])
                l1 = struct.unpack("!i", b[28:32])[0] - 4
                tgt = b[32 : 32 + l1]
                l2 = struct.unpack("!i", b[32 + l1 : 36 + l1])[0] - 4
                cmd = b[36 + l1 : 36 + l1 + l2].decode("utf-8")
                l3 = struct.unpack("!i", b[36 + l1 + l2 : 40 + l1 + l2])[0] - 4
                msgCookie = b[40 + l1 + l2 : 40 + l1 + l2 + l3]
                l4 = struct.unpack("!i", b[40 + l1 + l2 + l3 : 44 + l1 + l2 + l3])[0] - 4
                guid = b[44 + l1 + l2 + l3 : 44 + l1 + l2 + l3 + l4].decode("utf-8")
                # struct.unpack("!i", b[44 + l1 + l2 + l3 + l4 : 47 + l1 + l2 + l3 + l4]) - 4
                l5 = (
                    struct.unpack("!h", b[48 + l1 + l2 + l3 + l4 : 50 + l1 + l2 + l3 + l4])[
                        0
                    ]
                    - 2
                )
                rVersion = b[50 + l1 + l2 + l3 + l4 : 50 + l1 + l2 + l3 + l4 + l5].decode(
                    "utf-8"
                )
                l6 = (
                    struct.unpack(
                        "!i", b[50 + l1 + l2 + l3 + l4 + l5 : 54 + l1 + l2 + l3 + l4 + l5]
                    )[0]
                    - 4
                )
                signature = b[
                    54 + l1 + l2 + l3 + l4 + l5 : 54 + l1 + l2 + l3 + l4 + l5 + l6
                ]

                # bodyLen = (
                #     struct.unpack(
                #         "!i", b[54 + l1 + l2 + l3 + l4 + l5 + l6 : 58 + l1 + l2 + l3 + l4 + l5 + l6]
                #     )[0]
                #     - 4
                # )
                # body = b[
                #     58 + l1 + l2 + l3 + l4 + l5 + l6 : 58 + l1 + l2 + l3 + l4 + l5 + l6 + bodyLen
                # ]
                body = b[headLen:]

                if cmd =='':
                    raise Exception('cmd is empty')
                o = {
                    "msgCookie": msgCookie.hex(),
                    "buffer": body.hex(),
                    "cmd": cmd,
                    "seq": seq,
                    "uin": "10001",
                    "mode": "send",
                    "type": "unknown",
                    "source": 0,
                }
                s.post(f"http://{DOMAIN}/packet", data=json.dumps(o))
            except:
                pass
        elif t == "tea_decrypt":
            o = {
                "mode": "tea",
                "enc": False,
                "data": j["data"],
                "result": j["result"],
                "key": j["key"],
            }
            s.post(f"http://{DOMAIN}/tea", data=json.dumps(o))

            try:
                b = bytes.fromhex(j["result"])

                headLen = struct.unpack("!i", b[:4])[0]
                seq = struct.unpack("!i", b[4:8])[0]
                retCode = struct.unpack("!i", b[8:12])[0]
                l1 = struct.unpack("!i", b[12:16])[0] - 4
                extra = b[16 : 16 + l1].decode("utf-8")
                l2 = struct.unpack("!i", b[16 + l1 : 20 + l1])[0] - 4
                cmd = b[20 + l1 : 20 + l1 + l2].decode("utf-8")
                l3 = struct.unpack("!i", b[20 + l1 + l2 : 24 + l1 + l2])[0] - 4
                msgCookie = b[24 + l1 + l2 : 24 + l1 + l2 + l3]
                isCompress = struct.unpack("!i", b[24 + l1 + l2 + l3 : 28 + l1 + l2 + l3])[
                    0
                ]

                body = b[headLen:]
                
                if cmd =='':
                    raise Exception('cmd is empty')
                o = {
                    "msgCookie": msgCookie.hex(),
                    "buffer": body.hex(),
                    "cmd": cmd,
                    "seq": seq,
                    "uin": "10001",
                    "mode": "receive",
                    "type": "unknown",
                    "source": 0,
                }
                s.post(f"http://{DOMAIN}/packet", data=json.dumps(o))
            except:
                pass
        elif t == "aes_encrypt":
            o = {
                "mode": "aes",
                "enc": True,
                "data": j["data"],
                "result": j["result"] + " " + j["tag"],
                "key": j["key"] + " " + j["iv"],
            }
            s.post(f"http://{DOMAIN}/tea", data=json.dumps(o))
        elif t == "aes_decrypt":
            o = {
                "mode": "aes",
                "enc": False,
                "data": j["data"] + " " + j["tag"],
                "result": j["result"],
                "key": j["key"] + " " + j["iv"],
            }
            s.post(f"http://{DOMAIN}/tea", data=json.dumps(o))
    except:
        print(message)


def main():
    # pid = frida.spawn(program="/usr/bin/qq", argv=["--no-sandbox"])
    pid = frida.spawn(program="D:\\AppD\\QQNT\\QQ.exe", argv=["--enable-logging"])
    session = frida.attach(pid)
    frida.resume(pid)

    while True:
        with open("hook.js", encoding="utf-8") as f:
            script = session.create_script(f.read())
            script.on("message", on_message)
            script.load()
        sys.stdin.readline()


if __name__ == "__main__":
    main()
