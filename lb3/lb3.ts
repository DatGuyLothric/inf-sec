import * as bigInt from '../node_modules/big-integer/BigInteger';

// const area
const MSG = 'Just a simple message';

// main class
class Main {
    constructor() {}

    public run(): void {
        const keys: IKeys = RSA.generateKeys(256);
        console.log('Keys: ', keys);

        const encrypted: BigInteger = RSA.encrypt(RSA.encode(MSG), keys.n, keys.e);

        console.log('Message: ', MSG);
        console.log('Encrypted:', RSA.decode(encrypted));
        console.log('Decrypted:', RSA.decode(RSA.decrypt(encrypted, keys.d, keys.n)));
    }
}

// objects
class RSA {
    constructor() {}

    public static generateKeys(size: number): IKeys {
        const e: BigInteger = bigInt(65537);
        let p: BigInteger;
        let q: BigInteger;
        let mlp: BigInteger;
        do {
            p = randomPrime(size / 2);
            q = randomPrime(size / 2);
            mlp = bigInt.lcm(p.prev(), q.prev());
        } while (bigInt.gcd(e, mlp).notEquals(1) || p.minus(q).abs().shiftRight(size / 2 - 100).isZero());
        return {
            e, 
            n: p.multiply(q),
            d: e.modInv(mlp),
        };
    }

    public static encrypt(msg, n, e): BigInteger {
        return bigInt(msg).modPow(e, n);
    }
    
    public static decrypt(msg, d, n): BigInteger {
        return bigInt(msg).modPow(d, n); 
    }
    
    public static encode(msg): BigInteger {
        const chars: string = msg.split('').map(c => c.charCodeAt()).join('');
        return bigInt(chars);
    }
    
    public static decode(code): string {
        const stringified: string = code.toString();
        let string = '';
        for (let i = 0; i < stringified.length; i += 2) {
            let num = Number(stringified.substr(i, 2));
            if (num <= 30) {
                string += String.fromCharCode(Number(stringified.substr(i, 3)));
                i++;
            } else {
                string += String.fromCharCode(num);
            }
        }
        return string;
    }
}

// utils
function randomPrime(input: number): BigInteger {
    const min: BigInteger = bigInt.one.shiftLeft(input - 1);
    const max: BigInteger = bigInt.one.shiftLeft(input).prev();
    function prime(): BigInteger {
        let p: BigInteger = bigInt.randBetween(min, max);
        if (p.isProbablePrime(256)) {
            return p;
        } else {
            return prime();
        }
    }
    return prime();
}

type BigInteger = bigInt.BigInteger;

interface IKeys {
    e: BigInteger;
    n: BigInteger;
    d: BigInteger;
}

// app lifecycle
export const app: Main = new Main();
app.run();
