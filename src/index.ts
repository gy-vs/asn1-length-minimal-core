/**
 * Minimal ASN.1 TLV decoder with strict length parsing.
 *
 * Length forms (X.690 §8.1.3):
 *  - short form:      first octet 0x00–0x7F, the length is the octet itself
 *  - long form:       first octet 0x81–0xFE, low 7 bits count the following
 *                     big-endian length octets
 *  - indefinite form: first octet 0x80 (BER only; value ends at an EOC)
 *
 * DER (X.690 §10.1) requires the definite, minimal encoding: no indefinite
 * lengths, no long form for values below 128, no leading zero octets.
 */

export type LengthForm = 'short' | 'long' | 'indefinite';

export type LengthDiagnostic =
  | 'truncated' // length octets or declared content run past the buffer
  | 'indefinite' // 0x80 indefinite form where DER definiteness is required
  | 'non_minimal' // long form for a value < 128, or a leading zero octet
  | 'overflow'; // length exceeds the budget or the safe integer range

export class LengthError extends Error {
  readonly diagnostic: LengthDiagnostic;
  /** Offset at which the offending length field starts. */
  readonly offset: number;

  constructor(diagnostic: LengthDiagnostic, offset: number, message: string) {
    super(message);
    this.name = 'LengthError';
    this.diagnostic = diagnostic;
    this.offset = offset;
  }
}

export interface LengthOptions {
  /**
   * 'der' (default) rejects indefinite and non-minimal lengths.
   * 'ber' accepts every form, including indefinite.
   */
  mode?: 'der' | 'ber';
  /**
   * Budget: maximum accepted content length in octets.
   * Defaults to Number.MAX_SAFE_INTEGER.
   */
  maxLength?: number | bigint;
}

export interface LengthHeader {
  form: LengthForm;
  /** Content length in octets; null only for the BER indefinite form. */
  length: number | null;
  /** Octets consumed by the length field itself (1 + length-of-length). */
  headerSize: number;
}

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

/**
 * Parses the length field starting at `bytes[offset]`.
 *
 * Pure and total: it never mutates state and either returns a header or
 * throws a LengthError, so callers can keep their cursor untouched on
 * failure. The length is accumulated as a bigint, and the budget and
 * safe-range checks run before the value is narrowed to a number.
 */
export function parseLengthHeader(
  bytes: Uint8Array,
  offset: number,
  options: LengthOptions = {},
): LengthHeader {
  const mode = options.mode ?? 'der';
  const budget =
    options.maxLength === undefined ? MAX_SAFE : BigInt(options.maxLength);

  if (offset < 0 || offset >= bytes.length) {
    throw new LengthError('truncated', offset, 'missing length octet');
  }
  const first = bytes[offset];

  // Short form: 0–127 encoded in the initial octet itself.
  if (first < 0x80) {
    if (first > budget) {
      throw new LengthError(
        'overflow',
        offset,
        `length ${first} exceeds budget ${budget}`,
      );
    }
    return { form: 'short', length: first, headerSize: 1 };
  }

  // Indefinite form: BER only, never valid DER.
  if (first === 0x80) {
    if (mode === 'der') {
      throw new LengthError(
        'indefinite',
        offset,
        'indefinite length is not valid DER',
      );
    }
    return { form: 'indefinite', length: null, headerSize: 1 };
  }

  // Long form: low 7 bits count the subsequent length octets.
  const count = first & 0x7f;
  if (bytes.length - (offset + 1) < count) {
    throw new LengthError(
      'truncated',
      offset,
      `length-of-length ${count} exceeds available octets`,
    );
  }
  const lengthOctets = bytes.subarray(offset + 1, offset + 1 + count);

  if (mode === 'der' && lengthOctets[0] === 0x00) {
    throw new LengthError(
      'non_minimal',
      offset,
      'leading zero octet in long-form length',
    );
  }

  // Accumulate as bigint so an oversized length-of-length cannot wrap or
  // silently truncate before the range checks below.
  let value = 0n;
  for (const octet of lengthOctets) {
    value = (value << 8n) | BigInt(octet);
  }

  if (mode === 'der' && value < 128n) {
    throw new LengthError(
      'non_minimal',
      offset,
      `length ${value} must use the short form`,
    );
  }

  // Budget and safe-range checks, before narrowing bigint -> number.
  if (value > budget) {
    throw new LengthError(
      'overflow',
      offset,
      `length ${value} exceeds budget ${budget}`,
    );
  }
  if (value > MAX_SAFE) {
    throw new LengthError(
      'overflow',
      offset,
      `length ${value} exceeds the safe integer range`,
    );
  }

  return { form: 'long', length: Number(value), headerSize: 1 + count };
}

export interface Tlv {
  tag: number;
  /** Content length in octets. */
  length: number;
  /** Octets consumed by tag + length field. */
  headerSize: number;
  /** View onto the content octets of the input buffer. */
  value: Uint8Array;
  form: LengthForm;
}

/**
 * Cursor-based TLV reader. Every read is transactional: on failure the
 * reader throws and `offset` stays exactly where it was, so a caller may
 * recover or inspect the partial stream.
 */
export class TlvReader {
  #offset = 0;

  constructor(
    private readonly bytes: Uint8Array,
    private readonly options: LengthOptions = {},
  ) {}

  get offset(): number {
    return this.#offset;
  }

  get remaining(): number {
    return this.bytes.length - this.#offset;
  }

  get done(): boolean {
    return this.remaining === 0;
  }

  /** Reads one length header; the cursor advances only on success. */
  readLengthHeader(): LengthHeader {
    const header = parseLengthHeader(this.bytes, this.#offset, this.options);
    this.#offset += header.headerSize;
    return header;
  }

  /** Reads one tag/length/value triple; the cursor advances only on success. */
  readTlv(): Tlv {
    const start = this.#offset;

    if (this.remaining < 1) {
      throw new LengthError('truncated', start, 'missing tag octet');
    }
    const tag = this.bytes[start];

    const header = parseLengthHeader(this.bytes, start + 1, this.options);
    if (header.length === null) {
      throw new LengthError(
        'indefinite',
        start + 1,
        'indefinite-length values are not supported by readTlv',
      );
    }

    const valueStart = start + 1 + header.headerSize;
    // Range check before computing end = valueStart + length: the
    // subtraction form cannot overflow and proves end <= bytes.length.
    if (header.length > this.bytes.length - valueStart) {
      throw new LengthError(
        'truncated',
        start + 1,
        `declared length ${header.length} exceeds ` +
          `${this.bytes.length - valueStart} available octets`,
      );
    }
    const end = valueStart + header.length;

    const tlv: Tlv = {
      tag,
      length: header.length,
      headerSize: 1 + header.headerSize,
      value: this.bytes.subarray(valueStart, end),
      form: header.form,
    };
    this.#offset = end; // commit only after every check has passed
    return tlv;
  }
}

/** Decodes a single TLV from the start of `data` (DER by default). */
export function decodeTlv(data: Uint8Array, options?: LengthOptions): Tlv {
  return new TlvReader(data, options).readTlv();
}

export function decodeInteger(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}
