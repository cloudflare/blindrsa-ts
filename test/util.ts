import sjcl from '../src/sjcl/index.js';

export function hexToUint8(x: string): Uint8Array {
    if (x.startsWith('0x')) {
        x = x.slice(2);
    }
    return new Uint8Array(sjcl.codec.bytes.fromBits(sjcl.codec.hex.toBits(x)));
}

export function uint8ToHex(x: Uint8Array): string {
    return sjcl.codec.hex.fromBits(sjcl.codec.bytes.toBits(Array.from(x)));
}

export function hexNumToB64URL(x: string): string {
    if (x.startsWith('0x')) {
        x = x.slice(2);
    }
    return sjcl.codec.base64url.fromBits(sjcl.codec.hex.toBits(x));
}
