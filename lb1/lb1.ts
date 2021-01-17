import { readFileSync, writeFileSync } from 'fs';

// const area
const ALPHABET = 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя';


// main class
class Main {
    constructor() {}

    public run(): void {
        let data = readFileSync('lb1/data.txt', { encoding: 'utf-8' }).toString();
        let vim = readFileSync('lb1/vim.txt', { encoding: 'utf-8' }).toString();

        let encrypted = Ceasar.encrypt(data, 5);
        let dataDict = freq(encrypted);
        let vimDict = freq(vim);

        console.log('----------SINGLE----------');
        console.log(dataDict);
        console.log(vimDict);

        writeFileSync('lb1/encrypted-data.txt', encrypted, { encoding: 'utf-8' });
        writeFileSync('lb1/decrypted-data.txt', freqDecrypt(encrypted, dataDict, vimDict), { encoding: 'utf-8' });

        console.log('\n----------BIGRAMS----------');
        dataDict = freqBi(encrypted);
        vimDict = freqBi(vim);
        console.log(dataDict);
        console.log(vimDict);
        writeFileSync('lb1/decrypted-data-bi.txt', freqDecryptBi(encrypted, dataDict, vimDict), { encoding: 'utf-8' });
    }
}

// objects
class Ceasar {
    constructor() {}

    public static encrypt(data: string, shift: number): string {
        let ret = '';
        const aCode = 'а'.charCodeAt(0);
        const yaCode = 'я'.charCodeAt(0);
        for (let i of data) {
            let iCode = i.charCodeAt(0);
            if (iCode >= aCode && iCode <= yaCode) {
                ret += ((iCode + shift) > yaCode) ? String.fromCharCode(iCode + shift - ALPHABET.length + 1) : String.fromCharCode(iCode + shift);
            } else {
                ret += i;
            }
        }
        return ret;
    }

    public static decrypt(data: string, shift: number): string {
        let ret = '';
        const aCode = 'а'.charCodeAt(0);
        const yaCode = 'я'.charCodeAt(0);
        for (let i of data) {
            let iCode = i.charCodeAt(0);
            if (iCode >= aCode && iCode <= yaCode) {
                ret += ((iCode - shift) < aCode) ? String.fromCharCode(iCode - shift + ALPHABET.length - 1) : String.fromCharCode(iCode - shift);
            } else {
                ret += i;
            }
        }
        return ret;
    }
}

// utils
function freq(str: string): IDictItem[] {
    const aCode = 'а'.charCodeAt(0);
    const yaCode = 'я'.charCodeAt(0);
    let dict: IDictItem[] = [];
    str = str.toLowerCase();
    for (let i of str) {
        let iCode = i.charCodeAt(0);
        if (iCode >= aCode && iCode <= yaCode) {
            const item: IDictItem = dict.filter(a => a.c === i).length > 0 ? dict.filter(a => a.c === i)[0] : null;
            if (item) {
                item.f += 1;
            } else {
                dict.push({ c: i, f: 1 });
            }
        }
    }
    dict = dict.sort((a, b) => -(a.f - b.f));
    return dict;
}

function freqBi(str: string): IDictItem[] {
    let dict: IDictItem[] = [];
    for (let i of ALPHABET)
        for (let j of ALPHABET)
            dict.push({ c: i + j, f: 0 });
    for (let j = 0; j < str.length - 1; j++)
        if (dict.filter(a => a.c === str[j] + str[j + 1]).length > 0)
            dict.filter(a => a.c === str[j] + str[j + 1])[0].f += 1;
    dict = dict.sort((a, b) => -(a.f - b.f));
    return dict;
}

function freqDecrypt(str: string, a: IDictItem[], b: IDictItem[]): string {
    let ret = '';
    const aCode = 'а'.charCodeAt(0);
    const yaCode = 'я'.charCodeAt(0);
    for (let i of str) {
        let iCode = i.charCodeAt(0);
        if (iCode >= aCode && iCode <= yaCode) {
            ret += b[a.findIndex(a => a.c === i.toLowerCase())].c;
        } else {
            ret += i;
        }
    } 
    return ret;
}

function freqDecryptBi(str: string, a: IDictItem[], b: IDictItem[]): string {
    let ret = '';
    const aCode = 'а'.charCodeAt(0);
    const yaCode = 'я'.charCodeAt(0);
    for (let i = 0; i < str.length; i += 2) {
        let iCode = str[i].charCodeAt(0);
        let iCode2 = str[i + 1].charCodeAt(0);
        if (iCode >= aCode && iCode <= yaCode && iCode2 >= aCode && iCode2 <= yaCode) {
            ret += b[a.findIndex(a => a.c === str[i] + str[i + 1])].c;
        } else {
            ret += str[i] + str[i + 1];
        }
    } 
    return ret;
}

interface IDictItem {
    c: string;
    f: number;
}

// app lifecycle
const app: Main = new Main();
app.run();
