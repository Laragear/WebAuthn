<?php

namespace Laragear\WebAuthn\Enums;

/**
 * @see https://www.iana.org/assignments/webauthn/webauthn.xhtml
 * @see https://www.w3.org/TR/webauthn-2/#sctn-defined-attestation-formats
 */
enum Formats: string
{
    case Packed = 'packed';
    case Tpm = 'tpm';
    case AndroidKey = 'android-key';
    case AndroidSafetynet = 'android-safetynet';
    case FidoU2F = 'fido-u2f';
    case Apple = 'apple';
    case None = 'none';
}
