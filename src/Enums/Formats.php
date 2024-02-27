<?php

namespace Laragear\WebAuthn\Enums;

/**
 * @see https://www.iana.org/assignments/webauthn/webauthn.xhtml
 * @see https://www.w3.org/TR/webauthn-2/#sctn-defined-attestation-formats
 */
enum Formats: string
{
    case PACKED = 'packed';
    case TPM = 'tpm';
    case ANDROID_KEY = 'android-key';
    case ANDROID_SAFETYNET = 'android-safetynet';
    case FIDO_U2F = 'fido-u2f';
    case APPLE = 'apple';
    case NONE = 'none';
}
