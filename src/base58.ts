const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const BASE58_INDEX = new Map<string, number>(
  Array.from(BASE58_ALPHABET, (char, index) => [char, index]),
);

export function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";

  let leadingZeroes = 0;
  while (leadingZeroes < bytes.length && bytes[leadingZeroes] === 0) {
    leadingZeroes++;
  }

  let value = 0n;
  for (const byte of bytes) {
    value = value * 256n + BigInt(byte);
  }

  let encoded = "";
  while (value > 0n) {
    const index = Number(value % 58n);
    encoded = BASE58_ALPHABET[index] + encoded;
    value /= 58n;
  }

  return BASE58_ALPHABET[0].repeat(leadingZeroes) + encoded;
}

export function base58Decode(value: string): Uint8Array {
  if (value.length === 0) return new Uint8Array();

  let leadingZeroes = 0;
  while (
    leadingZeroes < value.length &&
    value[leadingZeroes] === BASE58_ALPHABET[0]
  ) {
    leadingZeroes++;
  }

  let decoded = 0n;
  for (const char of value) {
    const digit = BASE58_INDEX.get(char);
    if (digit === undefined) {
      throw new Error("Invalid base58 character.");
    }
    decoded = decoded * 58n + BigInt(digit);
  }

  const bytes: number[] = [];
  while (decoded > 0n) {
    bytes.unshift(Number(decoded % 256n));
    decoded /= 256n;
  }

  return Uint8Array.from([...Array(leadingZeroes).fill(0), ...bytes]);
}
