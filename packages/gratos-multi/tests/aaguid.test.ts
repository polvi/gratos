import { describe, expect, test } from 'bun:test';
import { providerName } from '../src/aaguid';

describe('providerName', () => {
    test('maps well-known passkey providers, case-insensitively', () => {
        expect(providerName('fbfc3007-154e-4ecc-8c0b-6e020557d7bd')).toBe('iCloud Keychain');
        expect(providerName('EA9B8D66-4D01-1D21-3CE4-B6B48CB575D4')).toBe('Google Password Manager');
        expect(providerName('bada5566-a7aa-401f-bd96-45619a55120d')).toBe('1Password');
        expect(providerName('ee882879-721c-4913-9775-3dfcce97072a')).toBe('YubiKey 5');
    });

    test('unknown, zero, and missing AAGUIDs give null', () => {
        expect(providerName('00000000-0000-0000-0000-000000000000')).toBeNull();
        expect(providerName('12345678-1234-1234-1234-123456789abc')).toBeNull();
        expect(providerName('')).toBeNull();
        expect(providerName(null)).toBeNull();
        expect(providerName(undefined)).toBeNull();
    });
});
