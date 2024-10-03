
const tea_encrypt = 0x182257261;
const tea_decrypt = 0x1822574CB;

const aes_encrypt = 0x18076689F;
const aes_decrypt = 0x180766DCF;

function resolveAddress(baseAddr, addr) {
    const idaBase = 0x180000000; // Enter the base address of jvm.dll as seen in your favorite disassembler (here IDA)
    const offset = ptr(addr).sub(idaBase); // Calculate offset in memory from base address in IDA database
    const result = ptr(baseAddr).add(offset); // Add current memory base address to offset of function to monitor
    console.log('[+] New addr=' + result); // Write location of function in memory to console
    return result;
}

function reverseAddress(baseAddr, addr) {
    const idaBase = 0x180000000; // Enter the base address of jvm.dll as seen in your favorite disassembler (here IDA)
    const offset = ptr(addr).sub(ptr(baseAddr)); // Add current memory base address to offset of function to monitor
    const result = ptr(idaBase).add(offset); // Calculate offset in memory from base address in IDA database
    console.log('[+] Reverse addr=' + result); // Write location of function in memory to console
    return result;
}

function PrintLog(log) {
    send(JSON.stringify(log))
}

async function main() {
    var baseAddr;
    while (true) {
        baseAddr = Module.findBaseAddress('wrapper.node');
        if (baseAddr != null) break;
    }
    console.log('[+] wrapper.node baseAddr: ' + baseAddr);

    function bytesToHex(arrayBuffer) {
        var bytes = new Uint8Array(arrayBuffer)
        for (var hex = [], i = 0; i < bytes.length; i++) {
            hex.push((bytes[i] >>> 4).toString(16));
            hex.push((bytes[i] & 0xF).toString(16));
        }
        return hex.join("");
    }
    
    // const log1 = []; // Here we use the function address as seen in our disassembler
    // for (var i = 0; i < log1.length; i++) {
    //     Interceptor.attach(resolveAddress(baseAddr, log1[i]), {
    //         // When function is called, print out its parameters
    //         onEnter(args) {
    //             var log = Memory.readCString(args[4].readPointer())
    //             if (log.search('{}') != -1)
    //                 log.replace('{}', Memory.readCString(args[5]));
    //             console.log('[+] log1 Arg: type=' + args[0] + ',file=' + Memory.readCString(args[1]) + ',line=' + args[2] + ',subtype=' + Memory.readCString(args[3]) + ',info=' + log);
    //             // console.log('[+] Caller ' + this.returnAddress + ' ' + reverseAddress(baseAddr, this.returnAddress));
    //         },
    //     });
    // }

    // const log2 = []; // Here we use the function address as seen in our disassembler
    // for (var i = 0; i < log2.length; i++) {
    //     Interceptor.attach(resolveAddress(baseAddr, log2[i]), {
    //         // When function is called, print out its parameters
    //         onEnter(args) {
    //             var log = Memory.readCString(args[5].readPointer())
    //             var i = 5;
    //             while (log.search('{}') != -1) {
    //                 log = log.replace('{}', Memory.readCString(args[++i]));
    //             }
    //             console.log('[+] log2 Arg: from=' + Memory.readCString(args[0]) + ' type=' + args[1] + ',file=' + Memory.readCString(args[2]) + ',line=' + args[3] + ',subtype=' + Memory.readCString(args[4]) + ',info=' + log);
    //             // console.log('[+] Caller ' + this.returnAddress + ' ' + reverseAddress(baseAddr, this.returnAddress));
    //         },
    //     });
    // }

    const readVector = (x) => x.readPointer().readByteArray(+x.add(8).readPointer().sub(x.readPointer()));
    // AES加密算法
    Interceptor.attach(resolveAddress(baseAddr, aes_encrypt), {
        onEnter: function (args) {
            //console.log("AES_encrypt START======================")
            this.data = readVector(args[0])
            this.key = readVector(args[1])
            this.iv = readVector(args[2])
            this.tag = args[3]
            this.result = args[4]
            //console.log("AES_encrypt => size:", dataSize, "key:", bytesToHex(key), "iv:", bytesToHex(iv), "data:", bytesToHex(data))

        },
        onLeave: function () {
            var resultSize = this.result.add(0x4).readPointer().sub(this.result.readPointer())
            // console.log("tag", bytesToHex(this.out1.readPointer().readByteArray(0x10)))
            // console.log("data", bytesToHex(this.out2.readPointer().readByteArray(resultSize.toInt32())))
            // console.log("AES_encrypt END========================")
            PrintLog({
                "type": "aes_encrypt",
                "data": bytesToHex(this.data),
                "key": bytesToHex(this.key),
                "iv": bytesToHex(this.iv),
                "result": bytesToHex(readVector(this.result)),
                "tag": bytesToHex(readVector(this.tag))
            })
        }
    })

    // AES解密算法
    Interceptor.attach(resolveAddress(baseAddr, aes_decrypt), {
        onEnter: function (args) {
            //console.log("AES_decrypt START======================")
            this.data = readVector(args[0])
            this.key = readVector(args[1])
            this.iv = readVector(args[2])
            this.tag = readVector(args[3])
            this.result = args[4]
            // console.log("AES_decrypt => size:", dataSize, "key:", bytesToHex(key), "iv:", bytesToHex(iv), "data:", bytesToHex(data))
        },
        onLeave: function () {
            // console.log("tag", bytesToHex(this.out1.readPointer().readByteArray(0x10)))
            // console.log("data", bytesToHex(this.out2.readPointer().readByteArray(resultSize.toInt32())))
            // console.log("AES_decrypt END========================")
            PrintLog({
                "type": "aes_decrypt",
                "data": bytesToHex(this.data),
                "tag": bytesToHex(this.tag),
                "key": bytesToHex(this.key),
                "iv": bytesToHex(this.iv),
                "result": bytesToHex(readVector(this.result)),
            })
        }
    })

    // // TEA加密
    // Interceptor.attach(resolveAddress(baseAddr, tea_encrypt), {
    //     onEnter: function (args) {
    //         this.data = args[0].readByteArray(args[1].toInt32())
    //         this.key = args[2].readByteArray(args[3].toInt32())
    //         this.out = args[4]
    //         this.out_len = args[5]
    //         //PrintLog({"key":"encode","size:": this.context.edx, "key:": bytesToHex(key), "data:": bytesToHex(data)})
    //     },
    //     onLeave: function () {
    //         PrintLog({
    //             "type": "tea_encrypt",
    //             "data": bytesToHex(this.data),
    //             "key": bytesToHex(this.key),
    //             "result": bytesToHex(this.out.readByteArray(this.out_len.readPointer().toInt32()))
    //         })
    //     }
    // })
    // // TEA解密
    // Interceptor.attach(resolveAddress(baseAddr, tea_decrypt), {
    //     onEnter: function (args) {
    //         this.data = args[0].readByteArray(args[1].toInt32())
    //         this.key = args[2].readByteArray(args[3].toInt32())
    //         this.out = args[4]
    //         this.out_len = args[5]
    //     },
    //     onLeave: function () {
    //         PrintLog({
    //             "type": "tea_decrypt",
    //             "data": bytesToHex(this.data),
    //             "key": bytesToHex(this.key),
    //             "result": bytesToHex(this.out.readByteArray(this.out_len.readPointer().toInt32()))
    //         })
    //     }
    // })
}

main();