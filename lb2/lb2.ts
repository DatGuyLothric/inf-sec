// main class
class Main {
    constructor() {}

    public run(): void {
        const a: IUser = defaultUser();
        const b: IUser = defaultUser();

        const p = generatePrimeNumber(10000);
        const g = generatePrimeNumber(5000);

        a.privateKey = 4;
        a.publicKey = DH.generatePublicKey(a.privateKey, p, g);
        b.privateKey = 3;
        b.publicKey = DH.generatePublicKey(b.privateKey, p, g);

        a.sharedKey = DH.generateSharedKey(b.publicKey, a.privateKey, p);
        b.sharedKey = DH.generateSharedKey(a.publicKey, b.privateKey, p);

        console.log('User A: ', a);
        console.log('User B: ', b);
    }
}

// objects
class DH {
    constructor() {}

    public static generatePublicKey(privateKey: number, p: number, g: number): number {
        return Math.pow(g, privateKey) % p;
    }

    public static generateSharedKey(publicKey: number, privateKey: number, p: number): number {
        return Math.pow(publicKey, privateKey) % p;
    }
}

interface IUser {
    privateKey: number;
    publicKey: number;
    sharedKey: number;
}

// utils
function isPrimeNumber(number: number): boolean {
    if (number % 1 || number < 2)
        return false;
	const q = Math.sqrt(number);
	for (let i = 2; i <= q; i++)
		if (number % i === 0)
			return false;
	return true;
}

function generatePrimeNumber(number: number): number {
	let prime: number;
	while (!prime && isSafeInteger(number)) {
		prime = isPrimeNumber(number)? number : null;
		number++;
	}
	return prime;
}

function isSafeInteger(number: number): boolean {
    return number > 0 && number < Number.MAX_SAFE_INTEGER;
}

function defaultUser(): IUser {
    return {
        privateKey: 0,
        publicKey: 0,
        sharedKey: 0
    }
}

// app lifecycle
export const app: Main = new Main();
app.run();
