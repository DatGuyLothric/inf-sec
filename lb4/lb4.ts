import * as crypto from 'crypto';
import * as BigNum from 'bignum';

// main class
class Main {
    constructor() {}

    public run(): void {
        let a: Buffer;
        let b: Buffer;
        const salt: Buffer = new Buffer("salt");
        const username: Buffer = new Buffer("username");
        const password: Buffer = new Buffer("password");
        const verifier: Buffer = computeVerifier(params[4096], salt, username, password);

        const generate = () => {
            genKey(64, function(err, key) {
                a = key;
                genKey(32, function(err, key) {
                    b = key;
                    compute();
                });
            });
        };

        const compute = () => {
            const client: Client = new Client(params[4096], salt, username, password, a);
            const A: Buffer = client.computeA();

            const server: Server = new Server(params[4096], verifier, b);
            const B: Buffer = server.computeB();
            server.setA(A);

            client.computeM1();
            setTimeout(() => {
                client.setB(B);
                client.computeM1();

                const M1: Buffer = client.computeM1();
                const M2: Buffer = server.checkM1(M1);

                const clientK: Buffer = client.computeK();
                const serverK: Buffer = server.computeK();

                console.log('Username: ', username.toString());
                console.log('Password: ', password.toString());
                console.log('Salt: ', salt.toString());
                console.log('A: ', A.readBigInt64BE());
                console.log('B: ', B.readBigInt64BE());
                console.log('M1: ', M1.readBigInt64BE());
                console.log('M2: ', M2.readBigInt64BE());
                console.log('Server K: ', serverK.readBigInt64BE());
                console.log('Client K: ', clientK.readBigInt64BE());
            }, 3000)
        }

        generate();
    }
}

// objects
class Server {
    public readonly private: IServerParams;
  
    constructor(params: ISRPParams, verifierBuf: Buffer, secret2Buf: Buffer) {
        const kNum: BigNum = getk(params);
        const vNum: BigNum = BigNum.fromBuffer(verifierBuf);
        const bNum: BigNum = BigNum.fromBuffer(secret2Buf);
        this.private = {
            params: params,
            kNum: kNum,
            bNum: bNum,
            vNum: vNum,
            BBuf: getB(params, kNum, vNum, bNum),
        };
    }
  
    public computeB(): Buffer {
        return this.private.BBuf;
    }
  
    public setA(ABuf: Buffer): void {
        const p: IServerParams = this.private;
        const ANum: BigNum = BigNum.fromBuffer(ABuf)
        const uNum: BigNum = getu(p.params, ABuf, p.BBuf);
        const SBuf: Buffer = serverGetS(p.params, p.vNum, ANum, p.bNum, uNum);
        p.KBuf = getK(p.params, SBuf);
        p.M1Buf = getM1(p.params, ABuf, p.BBuf, SBuf);
        p.M2Buf = getM2(p.params, ABuf, p.M1Buf, p.KBuf);
        p.uNum = uNum;
        p.SBuf = SBuf;
    }
  
    public checkM1(clientM1Buf: Buffer): Buffer {
        if (!equal(this.private.M1Buf, clientM1Buf))
            throw new Error("Wrong Password");
        return this.private.M2Buf;
    }
  
    public computeK(): Buffer {
        return this.private.KBuf;
    }
}

class Client {
    public readonly private: IClientParams;
  
    constructor(params: ISRPParams, saltBuf: Buffer, usernameBuf: Buffer, passwordBuf: Buffer, secret1Buf: Buffer) {
        const aNum: BigNum = BigNum.fromBuffer(secret1Buf);
        this.private = {
            params: params,
            kNum: getk(params),
            xNum: getx(params, saltBuf, usernameBuf, passwordBuf),
            aNum: aNum,
            ABuf: getA(params, aNum)
        }
    }
  
    public computeA(): Buffer {
        return this.private.ABuf;
    }
  
    public setB(BBuf: Buffer): void {
        const p: IClientParams = this.private;
        const BNum: BigNum = BigNum.fromBuffer(BBuf);
        const uNum: BigNum = getu(p.params, p.ABuf, BBuf);
        const SBuf: Buffer = clientGetS(p.params, p.kNum, p.xNum, p.aNum, BNum, uNum);
        p.KBuf = getK(p.params, SBuf);
        p.M1Buf = getM1(p.params, p.ABuf, BBuf, SBuf);
        p.M2Buf = getM2(p.params, p.ABuf, p.M1Buf, p.KBuf);
        p.uNum = uNum;
        p.SBuf = SBuf;
    }
  
    public computeM1(): Buffer {
        return this.private.M1Buf;
    }
  
    public checkM2(serverM2Buf: Buffer): void {
        if(!this.private.M2Buf || !equal(this.private.M2Buf, serverM2Buf))
            throw new Error("Wrong server!")
    }
  
    public computeK(): Buffer {
        return this.private.KBuf;
    }
}

interface IServerParams {
    params: ISRPParams;
    kNum: BigNum;
    bNum: BigNum;
    vNum: BigNum;
    BBuf: Buffer;
    KBuf?: Buffer;
    M1Buf?: Buffer;
    M2Buf?: Buffer;
    uNum?: BigNum;
    SBuf?: Buffer;
}

interface IClientParams {
    params: ISRPParams;
    kNum: BigNum;
    xNum: BigNum;
    aNum: BigNum;
    ABuf: Buffer;
    M1Buf?: Buffer;
    M2Buf?: Buffer;
    KBuf?: Buffer;
    uNum?: BigNum;
    SBuf?: Buffer;
}

interface ISRPParams {
    NLengthBits: number;
    N: BigNum;
    g: BigNum;
    hash: 'sha1' | 'sha256' | 'sha512';
}

// utils
function padTo(n: Buffer, len: number): Buffer {
    const padding = len - n.length;
    const result: Buffer = new Buffer(len);
    result.fill(0, 0, padding);
    n.copy(result, padding);
    return result;
}
  
function padToN(number: BigNum, params: ISRPParams): Buffer {
    return padTo(number.toBuffer(), params.NLengthBits / 8);
}
  
function getx(params: ISRPParams, salt: Buffer, I: Buffer, P: Buffer): BigNum {
    const hashIP: Buffer = crypto.createHash(params.hash).update(Buffer.concat([I, new Buffer(':'), P])).digest();
    const hashX: Buffer = crypto.createHash(params.hash).update(salt).update(hashIP).digest();
    return BigNum.fromBuffer(hashX);
}
  
const computeVerifier = (params: ISRPParams, salt: Buffer, I: Buffer, P: Buffer): Buffer => {
    const vNum = params.g.powm(getx(params, salt, I, P), params.N)
    return padToN(vNum, params);
}
  
function getk(params: ISRPParams): BigNum {
    const kBuf = crypto.createHash(params.hash).update(padToN(params.N, params)).update(padToN(params.g, params)).digest();
    return BigNum.fromBuffer(kBuf);
}
  
function genKey(bytes: number, callback: Function): void {
    crypto.randomBytes(bytes, (err: Error | null, buf: Buffer) => {
        if (err)
            return callback (err);
        return callback(null, buf);
    })
}
  
function getB(params: ISRPParams, k: BigNum, v: BigNum, b: BigNum): Buffer {
    const N: BigNum = params.N;
    const r: BigNum = k.mul(v).add(params.g.powm(b, N)).mod(N);
    return padToN(r, params);
}
  
function getA(params: ISRPParams, aNum: BigNum): Buffer {
    if (Math.ceil(aNum.bitLength() / 8) < 256 / 8)
        console.warn("getA: client key length", aNum.bitLength(), "is less than the recommended 256");
    return padToN(params.g.powm(aNum, params.N), params);
}
  
function getu(params: ISRPParams, A: Buffer, B: Buffer): BigNum {
    const uBuf: Buffer = crypto.createHash(params.hash).update(A).update(B).digest();
    return BigNum.fromBuffer(uBuf);
}
  
function clientGetS(params: ISRPParams, kNum: BigNum, xNum: BigNum, aNum: BigNum, BNum: BigNum, uNum: BigNum): Buffer {
    const g: BigNum = params.g;
    const N: BigNum = params.N;
    const S_num: BigNum = BNum.sub(kNum.mul(g.powm(xNum, N))).powm(aNum.add(uNum.mul(xNum)), N).mod(N);
    return padToN(S_num, params);
}
  
function serverGetS(params: ISRPParams, vNum: BigNum, ANum: BigNum, bNum: BigNum, uNum: BigNum): Buffer {
    const N: BigNum = params.N;
    const SNum: BigNum = ANum.mul(vNum.powm(uNum, N)).powm(bNum, N).mod(N);
    return padToN(SNum, params);
}

function getK(params: ISRPParams, SBuf: Buffer): Buffer {
    return crypto.createHash(params.hash).update(SBuf).digest();
}
  
function getM1(params: ISRPParams, ABuf: Buffer, BBuf: Buffer, SBuf: Buffer): Buffer {
    return crypto.createHash(params.hash).update(ABuf).update(BBuf).update(SBuf).digest();
}
  
function getM2(params: ISRPParams, ABuf: Buffer, MBuf: Buffer, KBuf: Buffer): Buffer {
    return crypto.createHash(params.hash).update(ABuf).update(MBuf).update(KBuf).digest();
}
  
function equal(buf1: Buffer, buf2: Buffer): boolean {
    let mismatch = buf1.length - buf2.length;
    if (mismatch)
        return false;
    for (let i = 0; i < buf1.length; i++)
        mismatch |= buf1[i] ^ buf2[i];
    return mismatch === 0;
}

function hex(s: string): BigNum {
    return new BigNum(s.split(/\s/).join(''), 16);
}

const params: { 4096: ISRPParams } = {
    4096: {
        NLengthBits: 4096,
        N: hex(' FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08'
                +'8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B'
                +'302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9'
                +'A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6'
                +'49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8'
                +'FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D'
                +'670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C'
                +'180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718'
                +'3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D'
                +'04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D'
                +'B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226'
                +'1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C'
                +'BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC'
                +'E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26'
                +'99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB'
                +'04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2'
                +'233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127'
                +'D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199'
                +'FFFFFFFF FFFFFFFF'),
        g: hex('05'),
        hash: 'sha256'
    },
}

// app lifecycle
export const app: Main = new Main();
app.run();
