import { describe, expect, it } from 'vitest';
import {
  decodeTlv,
  LengthError,
  parseLengthHeader,
  TlvReader,
  type LengthDiagnostic,
} from '../src/index.js';

const bytes = (...octets: number[]) => Uint8Array.from(octets);

/** Builds tag 0x04 + the given length octets + `valueBytes` filler octets. */
const tlv = (lengthOctets: number[], valueBytes: number) =>
  Uint8Array.from([0x04, ...lengthOctets, ...new Array(valueBytes).fill(0xaa)]);

const diagnosticOf = (fn: () => unknown): LengthDiagnostic => {
  try {
    fn();
  } catch (error) {
    expect(error).toBeInstanceOf(LengthError);
    return (error as LengthError).diagnostic;
  }
  throw new Error('expected a LengthError');
};

describe('short form', () => {
  it('accepts length 0', () => {
    const result = decodeTlv(bytes(0x04, 0x00));
    expect(result.form).toBe('short');
    expect(result.length).toBe(0);
    expect(result.value.length).toBe(0);
  });

  it('accepts 127, the largest short-form length', () => {
    const result = decodeTlv(tlv([0x7f], 127));
    expect(result.form).toBe('short');
    expect(result.length).toBe(127);
    expect(result.value.length).toBe(127);
  });

  it('rejects 127 encoded in long form (0x81 0x7f)', () => {
    expect(diagnosticOf(() => decodeTlv(tlv([0x81, 0x7f], 127)))).toBe(
      'non_minimal',
    );
  });
});

describe('long form', () => {
  it('accepts 128, the smallest long-form length', () => {
    const result = decodeTlv(tlv([0x81, 0x80], 128));
    expect(result.form).toBe('long');
    expect(result.length).toBe(128);
    expect(result.value.length).toBe(128);
  });

  it('accepts a multi-octet length', () => {
    const result = decodeTlv(tlv([0x82, 0x01, 0x00], 256));
    expect(result.length).toBe(256);
  });

  it('rejects leading zero octets', () => {
    expect(diagnosticOf(() => decodeTlv(tlv([0x82, 0x00, 0x80], 128)))).toBe(
      'non_minimal',
    );
    expect(
      diagnosticOf(() => decodeTlv(tlv([0x83, 0x00, 0x01, 0x00], 256))),
    ).toBe('non_minimal');
  });

  it('rejects a long-form value below 128', () => {
    expect(diagnosticOf(() => decodeTlv(tlv([0x81, 0x00], 0)))).toBe(
      'non_minimal',
    );
    expect(diagnosticOf(() => decodeTlv(tlv([0x81, 0x01], 1)))).toBe(
      'non_minimal',
    );
  });
});

describe('indefinite form (length-of-length zero, 0x80)', () => {
  it('is rejected in DER mode', () => {
    expect(diagnosticOf(() => decodeTlv(bytes(0x04, 0x80, 0x00, 0x00)))).toBe(
      'indefinite',
    );
  });

  it('is classified distinctly in BER mode', () => {
    const header = parseLengthHeader(bytes(0x80), 0, { mode: 'ber' });
    expect(header.form).toBe('indefinite');
    expect(header.length).toBeNull();
  });

  it('cannot be read as a definite TLV even in BER mode', () => {
    const reader = new TlvReader(bytes(0x04, 0x80, 0x00, 0x00), {
      mode: 'ber',
    });
    expect(diagnosticOf(() => reader.readTlv())).toBe('indefinite');
  });
});

describe('overflow and budget', () => {
  it('accepts Number.MAX_SAFE_INTEGER as a length', () => {
    // 2^53 - 1 = 0x1FFFFFFFFFFFFF, seven length octets.
    const header = parseLengthHeader(
      bytes(0x87, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
      0,
    );
    expect(header.length).toBe(Number.MAX_SAFE_INTEGER);
  });

  it('rejects 2^53, just past the safe range', () => {
    expect(
      diagnosticOf(() =>
        parseLengthHeader(
          bytes(0x87, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00),
          0,
        ),
      ),
    ).toBe('overflow');
  });

  it('rejects a 64-bit length without wrapping', () => {
    // 2^64 - 1 would silently truncate to 0 if narrowed to a machine word.
    expect(
      diagnosticOf(() =>
        parseLengthHeader(
          bytes(0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff),
          0,
        ),
      ),
    ).toBe('overflow');
  });

  it('rejects an oversized length-of-length instead of wrapping', () => {
    // 0xfe declares 126 length octets; all 0xff is ~2^1008.
    expect(
      diagnosticOf(() =>
        parseLengthHeader(bytes(0xfe, ...new Array(126).fill(0xff)), 0),
      ),
    ).toBe('overflow');
  });

  it('enforces the budget on long and short forms', () => {
    expect(
      diagnosticOf(() =>
        parseLengthHeader(bytes(0x81, 0x80), 0, { maxLength: 127 }),
      ),
    ).toBe('overflow');
    expect(
      diagnosticOf(() => parseLengthHeader(bytes(0x65), 0, { maxLength: 100 })),
    ).toBe('overflow');
    expect(
      parseLengthHeader(bytes(0x81, 0x80), 0, { maxLength: 128 }).length,
    ).toBe(128);
  });
});

describe('truncated input', () => {
  it('rejects an empty buffer and a bare tag', () => {
    expect(diagnosticOf(() => decodeTlv(bytes()))).toBe('truncated');
    expect(diagnosticOf(() => decodeTlv(bytes(0x04)))).toBe('truncated');
  });

  it('rejects a truncated long-form length', () => {
    // Declares two length octets but only one is present.
    expect(diagnosticOf(() => decodeTlv(bytes(0x04, 0x82, 0x01)))).toBe(
      'truncated',
    );
  });

  it('rejects a declared length beyond the buffer', () => {
    expect(diagnosticOf(() => decodeTlv(bytes(0x04, 0x05, 0xaa)))).toBe(
      'truncated',
    );
    expect(diagnosticOf(() => decodeTlv(tlv([0x81, 0x80], 10)))).toBe(
      'truncated',
    );
  });

  it('reports a huge declared length as truncated, not overflow', () => {
    // Length is exactly MAX_SAFE_INTEGER (in range) but the buffer is short.
    const data = bytes(0x04, 0x87, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
    expect(diagnosticOf(() => decodeTlv(data))).toBe('truncated');
  });
});

describe('cursor semantics', () => {
  it('does not move the cursor when a read fails', () => {
    const reader = new TlvReader(bytes(0x04, 0x81, 0x7f));
    expect(diagnosticOf(() => reader.readTlv())).toBe('non_minimal');
    expect(reader.offset).toBe(0);

    const short = new TlvReader(bytes(0x04, 0x82, 0x01));
    expect(diagnosticOf(() => short.readTlv())).toBe('truncated');
    expect(short.offset).toBe(0);
  });

  it('commits the cursor only after a full successful read', () => {
    const data = Uint8Array.from([0x02, 0x01, 0x05, 0x04, 0x02, 0xaa, 0xbb]);
    const reader = new TlvReader(data);

    const first = reader.readTlv();
    expect(first.tag).toBe(0x02);
    expect(reader.offset).toBe(3);

    const second = reader.readTlv();
    expect(second.tag).toBe(0x04);
    expect(Array.from(second.value)).toEqual([0xaa, 0xbb]);
    expect(reader.offset).toBe(data.length);
    expect(reader.done).toBe(true);
  });

  it('readLengthHeader is transactional too', () => {
    const reader = new TlvReader(bytes(0x81, 0x7f));
    expect(diagnosticOf(() => reader.readLengthHeader())).toBe('non_minimal');
    expect(reader.offset).toBe(0);
  });
});

describe('BER mode accepts what DER rejects', () => {
  it('accepts non-minimal long forms', () => {
    expect(parseLengthHeader(bytes(0x81, 0x7f), 0, { mode: 'ber' }).length).toBe(
      127,
    );
    expect(
      parseLengthHeader(bytes(0x82, 0x00, 0x80), 0, { mode: 'ber' }).length,
    ).toBe(128);
  });

  it('still enforces truncation and overflow', () => {
    expect(
      diagnosticOf(() => parseLengthHeader(bytes(0x82, 0x01), 0, { mode: 'ber' })),
    ).toBe('truncated');
    expect(
      diagnosticOf(() =>
        parseLengthHeader(bytes(0x87, 0x20, 0, 0, 0, 0, 0, 0), 0, {
          mode: 'ber',
        }),
      ),
    ).toBe('overflow');
  });
});
