import { describe, expect, it } from 'vitest';
import {
  decodeLength,
  decodeTlv,
  DerDecoder,
  DerError,
} from '../src/index.js';

function kindOf(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    return e instanceof DerError ? e.kind : 'other';
  }
  return 'none';
}

describe('decodeTlv short form', () => {
  it('decodes length 0', () => {
    const t = decodeTlv(Uint8Array.from([0x02, 0x00]));
    expect(t.length).toBe(0);
    expect(t.value).toHaveLength(0);
  });

  it('decodes length 127 (short form only)', () => {
    const data = new Uint8Array(129);
    data[0] = 0x04;
    data[1] = 127;
    data[128] = 0xaa;
    const t = decodeTlv(data);
    expect(t.length).toBe(127);
    expect(t.value).toHaveLength(127);
    expect(t.value[126]).toBe(0xaa);
  });

  it('rejects 127 encoded as long form 0x81 0x7f (non_minimal)', () => {
    // Exactly enough buffer for the claimed value: ambiguity must resolve
    // to non_minimal, not truncated/overflow.
    const data = new Uint8Array(3 + 127);
    data[0] = 0x04;
    data[1] = 0x81;
    data[2] = 0x7f;
    expect(kindOf(() => decodeTlv(data))).toBe('non_minimal');
  });
});

describe('decodeTlv long form boundary', () => {
  it('decodes length 128 via 0x81 0x80', () => {
    const data = new Uint8Array(3 + 128);
    data[0] = 0x04;
    data[1] = 0x81;
    data[2] = 0x80;
    data[130] = 0x55;
    const t = decodeTlv(data);
    expect(t.length).toBe(128);
    expect(t.value[127]).toBe(0x55);
  });

  it('decodes length 256 via 0x82 0x01 0x00', () => {
    const data = new Uint8Array(4 + 256);
    data[0] = 0x04;
    data[1] = 0x82;
    data[2] = 0x01;
    data[3] = 0x00;
    const t = decodeTlv(data);
    expect(t.length).toBe(256);
    expect(t.value).toHaveLength(256);
  });

  it('rejects leading zero 0x82 0x00 0x80 for 128 (non_minimal)', () => {
    const data = new Uint8Array(4 + 128);
    data[0] = 0x04;
    data[1] = 0x82;
    data[2] = 0x00;
    data[3] = 0x80;
    expect(kindOf(() => decodeTlv(data))).toBe('non_minimal');
  });

  it('rejects long-form zero 0x81 0x00 (non_minimal)', () => {
    const data = Uint8Array.from([0x04, 0x81, 0x00]);
    expect(kindOf(() => decodeTlv(data))).toBe('non_minimal');
  });

  it('rejects multi-octet long-form zero 0x82 0x00 0x00 (non_minimal)', () => {
    const data = Uint8Array.from([0x04, 0x82, 0x00, 0x00]);
    expect(kindOf(() => decodeTlv(data))).toBe('non_minimal');
  });
});

describe('indefinite length', () => {
  it('rejects BER indefinite 0x80 in DER mode', () => {
    const data = Uint8Array.from([0x04, 0x80, 0x01, 0x02, 0x00, 0x00]);
    expect(kindOf(() => decodeTlv(data))).toBe('indefinite');
  });

  it('is distinguished from truncated: 0x80 with no following bytes', () => {
    const data = Uint8Array.from([0x04, 0x80]);
    expect(kindOf(() => decodeTlv(data))).toBe('indefinite');
  });
});

describe('truncated input', () => {
  it('flags empty input', () => {
    expect(kindOf(() => decodeTlv(Uint8Array.of()))).toBe('truncated');
  });

  it('flags tag without length', () => {
    expect(kindOf(() => decodeTlv(Uint8Array.of(0x04)))).toBe('truncated');
  });

  it('flags truncated length: 0x82 with only one length octet', () => {
    expect(
      kindOf(() => decodeTlv(Uint8Array.from([0x04, 0x82, 0x01]))),
    ).toBe('truncated');
  });

  it('flags truncated length: 0x81 with no length octet', () => {
    expect(kindOf(() => decodeTlv(Uint8Array.of(0x04, 0x81)))).toBe(
      'truncated',
    );
  });

  it('flags declared short-form value past buffer end (overflow)', () => {
    // Claims 5, provides 2 value bytes: structurally complete, but the
    // declared end = offset + length runs past the buffer (no truncation
    // ambiguity with the length field itself).
    expect(
      kindOf(() => decodeTlv(Uint8Array.from([0x04, 0x05, 1, 2]))),
    ).toBe('overflow');
  });

  it('flags declared long-form value past buffer end (overflow)', () => {
    // Claims 128, provides 3 value bytes.
    expect(
      kindOf(() =>
        decodeTlv(Uint8Array.from([0x04, 0x81, 0x80, 1, 2, 3])),
      ),
    ).toBe('overflow');
  });
});

describe('overflow', () => {
  it('accepts the maximum safe length when the budget allows it', () => {
    // MAX_SAFE_INTEGER = 2^53-1 = 0x1fffffffffffff: minimal long form is
    // seven content octets -> 0x87.
    const data = Uint8Array.from([
      0x87, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    ]);
    const r = decodeLength(data, 0);
    expect(r.length).toBe(Number.MAX_SAFE_INTEGER);
    expect(r.end).toBe(8);
  });

  it('overflows one past MAX_SAFE_INTEGER (0x20000000000000)', () => {
    const data = Uint8Array.from([
      0x87, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]);
    expect(kindOf(() => decodeLength(data, 0))).toBe('overflow');
  });

  it('overflows a huge length-of-length 0xFF... (no integer wraparound)', () => {
    // 0xFF declares 127 length octets; the accumulated bigint far exceeds
    // MAX_SAFE_INTEGER -> overflow, and the oversized length-of-length
    // count itself cannot bypass the limit.
    const data = new Uint8Array(128);
    data[0] = 0xff;
    for (let i = 1; i < 128; i++) data[i] = 0xff;
    expect(kindOf(() => decodeLength(data, 0))).toBe('overflow');
  });

  it('flags declared length beyond buffer bounds as overflow', () => {
    // Well-formed minimal long form claiming 1000 bytes in a tiny buffer.
    const data = Uint8Array.from([0x04, 0x82, 0x03, 0xe8, 1, 2]);
    expect(kindOf(() => decodeTlv(data))).toBe('overflow');
  });

  it('cannot make end = offset + length wrap via range addition', () => {
    // 8-byte length near 2^53 with a leading zero is both non-minimal;
    // drop the zero to get 0x1fffffffffffff (MAX_SAFE), which is accepted
    // syntactically but fails the budget against the real buffer.
    const data = Uint8Array.from([
      0x04, 0x87, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
    ]);
    expect(kindOf(() => decodeTlv(data))).toBe('overflow');
  });
});

describe('cursor safety', () => {
  it('does not move the main cursor on failure', () => {
    const decoder = new DerDecoder(Uint8Array.of(0x04));
    expect(decoder.offset).toBe(0);
    expect(kindOf(() => decoder.readTlv())).toBe('truncated');
    expect(decoder.offset).toBe(0);

    // Cursor is still usable from the same position.
    const good = Uint8Array.from([0x02, 0x01, 0x05]);
    const d2 = new DerDecoder(good);
    expect(kindOf(() => d2.readTlv())).toBe('none');
    expect(d2.eof).toBe(true);
  });

  it('advances the cursor across sequential TLVs', () => {
    const data = Uint8Array.from([2, 1, 5, 4, 2, 9, 9]);
    const decoder = new DerDecoder(data);
    const a = decoder.readTlv();
    expect(a.tag).toBe(2);
    expect(a.length).toBe(1);
    expect(a.value[0]).toBe(5);
    const b = decoder.readTlv();
    expect(b.tag).toBe(4);
    expect(Array.from(b.value)).toEqual([9, 9]);
    expect(decoder.eof).toBe(true);
  });

  it('preserves cursor position when a later TLV in the stream is invalid', () => {
    const data = Uint8Array.from([2, 1, 5, 4, 0x81]);
    const decoder = new DerDecoder(data);
    decoder.readTlv();
    const before = decoder.offset;
    expect(kindOf(() => decoder.readTlv())).toBe('truncated');
    expect(decoder.offset).toBe(before);
    expect(decoder.remaining).toBe(2);
  });
});

describe('original smoke test', () => {
  it('decodes', () =>
    expect(decodeTlv(Uint8Array.from([2, 1, 5])).value[0]).toBe(5));
});
