export function hexToUint8(x: string): Uint8Array {
    if (x.startsWith('0x')) {
        x = x.substring(2);
    }
    return Uint8Array.from({ length: Math.floor(x.length / 2) }, (_, i) =>
        parseInt(x.substring(2 * i, 2 * i + 2), 16),
    );
}

export function uint8ToHex(x: Uint8Array): string {
    return Array.from(x)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

function b64ToB64URL(s: string) {
    return s.replace(/\+/g, '-').replace(/\//g, '_');
}

export function hexNumToB64URL(x: string): string {
    return b64ToB64URL(btoa(String.fromCharCode(...hexToUint8(x))));
}
