import type { SjclCodec } from 'sjcl';
import sjcl from '../src/sjcl';

export function hexToUint8(x: string): Uint8Array {
    if (x.startsWith('0x')) {
        x = x.slice(2);
    }
    const hexCodec: SjclCodec<string> = sjcl.codec.hex;
    const bytesCodec: SjclCodec<number[]> = sjcl.codec.bytes;
    return new Uint8Array(bytesCodec.fromBits(hexCodec.toBits(x)));
}

export function uint8ToHex(x: Uint8Array): string {
    const hexCodec: SjclCodec<string> = sjcl.codec.hex;
    const bytesCodec: SjclCodec<number[]> = sjcl.codec.bytes;
    return hexCodec.fromBits(bytesCodec.toBits(Array.from(x)));
}

export function hexNumToB64URL(x: string): string {
    if (x.startsWith('0x')) {
        x = x.slice(2);
    }

    const hexCodec: SjclCodec<string> = sjcl.codec.hex;
    const b64Codec: SjclCodec<string> = sjcl.codec.base64url;
    return b64Codec.fromBits(hexCodec.toBits(x));
}
