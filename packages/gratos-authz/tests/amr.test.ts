import { describe, expect, test } from 'bun:test';
import { AMR_RANK, isAmr, meetsMinAmr, parseMinAmr } from '../src/amr';
import { ApiError } from '../src/model';

describe('parseMinAmr', () => {
    test('absent → null', () => {
        expect(parseMinAmr(undefined)).toBeNull();
        expect(parseMinAmr(null)).toBeNull();
    });

    test('valid values pass through', () => {
        expect(parseMinAmr('webauthn')).toBe('webauthn');
        expect(parseMinAmr('device')).toBe('device');
        expect(parseMinAmr('key')).toBe('key');
        expect(parseMinAmr('otp')).toBe('otp');
    });

    test('invalid value throws 400', () => {
        expect(() => parseMinAmr('password')).toThrow(ApiError);
        expect(() => parseMinAmr('WEBAUTHN')).toThrow();
        expect(() => parseMinAmr(3)).toThrow();
    });
});

describe('meetsMinAmr', () => {
    test('stronger or equal satisfies', () => {
        expect(meetsMinAmr('webauthn', 'key')).toBe(true);
        expect(meetsMinAmr('webauthn', 'webauthn')).toBe(true);
        expect(meetsMinAmr('device', 'key')).toBe(true);
        expect(meetsMinAmr('key', 'key')).toBe(true);
    });

    test('weaker never satisfies', () => {
        expect(meetsMinAmr('key', 'device')).toBe(false);
        expect(meetsMinAmr('device', 'webauthn')).toBe(false);
        expect(meetsMinAmr('key', 'webauthn')).toBe(false);
        expect(meetsMinAmr('otp', 'key')).toBe(false);
    });

    test('a code session only meets an otp floor', () => {
        expect(meetsMinAmr('otp', 'otp')).toBe(true);
        expect(meetsMinAmr('key', 'otp')).toBe(true);
    });

    test('missing/unknown amr fails closed', () => {
        expect(meetsMinAmr(undefined, 'key')).toBe(false);
        expect(meetsMinAmr('', 'key')).toBe(false);
        expect(meetsMinAmr('bogus', 'key')).toBe(false);
    });
});

describe('ranking sanity', () => {
    test('webauthn > device > key', () => {
        expect(AMR_RANK.webauthn).toBeGreaterThan(AMR_RANK.device);
        expect(AMR_RANK.device).toBeGreaterThan(AMR_RANK.key);
    });
    test('isAmr guards the union', () => {
        expect(isAmr('webauthn')).toBe(true);
        expect(isAmr('nope')).toBe(false);
    });
});
