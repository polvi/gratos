// Authenticator AAGUID → human display name for the credential list. Passkey
// providers publish stable AAGUIDs (community list:
// github.com/passkeydeveloper/passkey-authenticator-aaguids). The name is the
// default label for a passkey whose owner gave it none. Unknown / all-zero
// AAGUIDs (attestation "none" from many roaming keys) map to null.

const PROVIDERS: Record<string, string> = {
    'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'iCloud Keychain',
    'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': 'iCloud Keychain (managed)',
    'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Google Password Manager',
    'adce0002-35bc-c60a-648b-0b25f1f05503': 'Chrome on Mac',
    '08987058-cadc-4b81-b6e1-30de50dcbe96': 'Windows Hello',
    '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': 'Windows Hello',
    '6028b017-b1d4-4c02-b4b3-afcdafc96bb2': 'Windows Hello',
    'bada5566-a7aa-401f-bd96-45619a55120d': '1Password',
    'd548826e-79b4-db40-a3d8-11116f7e8349': 'Bitwarden',
    '531126d6-e717-415c-9320-3d9aa6981239': 'Dashlane',
    '50726f74-6f6e-5061-7373-50726f746f6e': 'Proton Pass',
    '53414d53-554e-4700-0000-000000000000': 'Samsung Pass',
    'f3809540-7f14-49c1-a8b3-8f813b225541': 'Enpass',
    'fdb141b2-5d84-443e-8a35-4698c205a502': 'KeePassXC',
    'b5397666-4885-aa6b-cebf-e52262a439a2': 'Chromium browser',
    'ee882879-721c-4913-9775-3dfcce97072a': 'YubiKey 5',
    'fa2b99dc-9e39-4257-8f92-4a30d23c4118': 'YubiKey 5 NFC',
    '2fc0579f-8113-47ea-b116-bb5a8db9202a': 'YubiKey 5 NFC',
    'cb69481e-8ff7-4039-93ec-0a2729a154a8': 'YubiKey 5 NFC',
    'c5ef55ff-ad9a-4b9f-b580-adebafe026d0': 'YubiKey 5Ci',
    '73bb0cd4-e502-49b8-9c6f-b59445bf720b': 'YubiKey 5 FIPS',
    'd8522d9f-575b-4866-88a9-ba99fa02f35b': 'YubiKey Bio',
    '149a2021-8ef6-4133-96b8-81f8d5b7f1f5': 'Security Key by Yubico',
    '6d44ba9b-f6ec-2e49-b930-0c8fe920cb73': 'Security Key NFC by Yubico',
    '0bb43545-fd2c-4185-87dd-feb0b2916ace': 'Security Key NFC by Yubico',
    '85203421-48f9-4355-9bc8-8a53846e5083': 'YubiKey 5Ci FIPS',
};

const ZERO = '00000000-0000-0000-0000-000000000000';

/** Display name for a known passkey provider / authenticator model, else null. */
export function providerName(aaguid: string | null | undefined): string | null {
    if (!aaguid) return null;
    const key = aaguid.trim().toLowerCase();
    if (key === ZERO) return null;
    return PROVIDERS[key] ?? null;
}
