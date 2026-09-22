// Minimal strict DER TLV decoder.
//
// Length octets (X.690 8.1.3):
//   short form:  0xxxxxxx            -> length 0..127
//   long form:   1nnnnnnn, n octets  -> length 128..MAX_SAFE_INTEGER
//   indefinite:  10000000 (0x80)     -> BER only, forbidden in DER
//
// DER additionally requires the shortest possible long-form encoding:
// the first content-length octet must not be zero, and values 0..127
// must use the short form.

export type LengthErrorKind =
  | 'non_minimal'
  | 'indefinite'
  | 'overflow'
  | 'truncated';

export class DerError extends Error {
  readonly kind: LengthErrorKind;
  constructor(kind: LengthErrorKind, message: string) {
    super(message);
    this.name = 'DerError';
    this.kind = kind;
  }
}

export interface Tlv {
  tag: number;
  length: number;
  value: Uint8Array;
}

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

function fail(kind: LengthErrorKind, message: string): never {
  throw new DerError(kind, message);
}

/**
 * Parse DER length octets beginning at `offset`.
 *
 * Accumulates the length in a bigint so a huge length-of-length or a
 * declared length beyond the safe-integer range is detected as `overflow`
 * rather than wrapping. On success the length is only converted to a Number
 * after proving it is <= Number.MAX_SAFE_INTEGER.
 *
 * `budget` is the number of bytes available from `offset` (header octets
 * plus content); it enables a declared-end check before computing
 * end = offset + length.
 *
 * Throws DerError; callers decide whether to advance their cursor.
 */
export function decodeLength(
  data: Uint8Array,
  offset: number,
  budget?: number,
): { length: number; end: number } {
  if (offset >= data.length) fail('truncated', 'missing length octet');

  const first = data[offset];

  // Short form: 0xxxxxxx, length 0..127 in one octet.
  if ((first & 0x80) === 0) {
    // One header octet plus `first` content octets must fit the budget.
    if (budget !== undefined && 1 + first > budget) {
      fail('overflow', `declared length ${first} exceeds input bounds`);
    }
    return { length: first, end: offset + 1 };
  }

  // BER indefinite length 0x80: never valid in DER.
  if (first === 0x80) {
    fail('indefinite', 'indefinite length form is not permitted in DER');
  }

  // Long form: low seven bits give the number of following length octets.
  const numBytes = first & 0x7f;
  const headerLen = 1 + numBytes;

  // Truncated length: the declared length octets are not all present.
  if (offset + headerLen > data.length) {
    fail('truncated', `length needs ${numBytes} octet(s), input truncated`);
  }

  // Bigint accumulation makes an oversized length-of-length incapable of
  // bypassing limits: every octet contributes faithfully.
  let raw = 0n;
  for (let i = 0; i < numBytes; i++) {
    raw = (raw << 8n) | BigInt(data[offset + 1 + i]);
  }

  // A zero value can only be encoded in the short form (0x00); likewise
  // a leading zero content octet means a non-shortest long-form encoding.
  if (raw === 0n) {
    fail('non_minimal', 'zero length must use the short form');
  }
  if (data[offset + 1] === 0x00) {
    fail('non_minimal', 'leading zero in long-form length');
  }

  // Values 0..127 have a one-octet short form, so a long form encoding
  // them (e.g. 0x81 0x7f for 127) is not the minimal encoding.
  if (raw < 128n) {
    fail('non_minimal', `length ${raw} must use the short form`);
  }

  // Range check before any Number conversion.
  if (raw > MAX_SAFE) {
    fail('overflow', `length ${raw} exceeds MAX_SAFE_INTEGER`);
  }

  const length = Number(raw);

  // Budget check before end = offset + length; done in bigint so the
  // addition can never wrap. `headerLen + raw` is the total span relative
  // to `offset`.
  if (budget !== undefined && BigInt(headerLen) + raw > BigInt(budget)) {
    fail('overflow', `declared length ${length} exceeds input bounds`);
  }

  return { length, end: offset + headerLen };
}

/** Cursor-based DER reader; failed reads never move the main cursor. */
export class DerDecoder {
  readonly data: Uint8Array;
  offset: number;

  constructor(data: Uint8Array, offset = 0) {
    this.data = data;
    this.offset = offset;
  }

  get remaining(): number {
    return this.data.length - this.offset;
  }

  get eof(): boolean {
    return this.offset >= this.data.length;
  }

  /** Read one TLV. `this.offset` is only advanced on full success. */
  readTlv(): Tlv {
    const data = this.data;
    const start = this.offset;

    if (start >= data.length) fail('truncated', 'missing tag octet');

    // Single-octet tag only; parsing happens from a local cursor.
    const tag = data[start];
    const pos = start + 1;

    // decodeLength performs the budget check against the remaining input
    // (its end arithmetic is relative to `pos`) and throws, leaving `start`
    // untouched, if the declared end is out of bounds. Reaching here proves
    // headerEnd + length <= data.length.
    const { length, end: headerEnd } = decodeLength(
      data,
      pos,
      data.length - pos,
    );

    const valueEnd = headerEnd + length;
    this.offset = valueEnd;
    return { tag, length, value: data.slice(headerEnd, valueEnd) };
  }
}

export function decodeTlv(data: Uint8Array): Tlv {
  return new DerDecoder(data).readTlv();
}

export function decodeInteger(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}
