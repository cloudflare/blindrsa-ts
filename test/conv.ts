import { Buffer } from 'node:buffer';

export function hexNumToB64URL(x: string): string {
    if (x.startsWith('0x')) {
        x = x.slice(2);
    }
    return Buffer.from(x, 'hex').toString('base64url');
}

export function hexToUint8(x: string): Uint8Array {
    if (x.startsWith('0x')) {
        x = x.slice(2);
    }
    return new Uint8Array(Buffer.from(x, 'hex'));
}

export function uint8ToHex(x: Uint8Array): string {
    return Buffer.from(x).toString('hex');
}
