<?php

namespace Laragear\WebAuthn\Enums;

/**
 * @see https://www.iana.org/assignments/webauthn/webauthn.xhtml
 * @see https://www.w3.org/TR/webauthn-2/#sctn-extensions
 */
enum Extension: string
{
    case APPID = 'appid';
    case TX_AUTH_SIMPLE = 'txAuthSimple';
    case TX_AUTH_GENERIC = 'txAuthGeneric';
    case AUTHN_SEL = 'authnSel';
    case EXTS = 'exts';
    case UVI = 'uvi';
    case LOC = 'loc';
    case UVM = 'uvm';
    case CRED_PROTECT = 'credProtect';
    case CRED_BLOB = 'credBlob';
    case LARGE_BLOB_KEY = 'largeBlobKey';
    case MIN_PIN_LENGTH = 'minPinLength';
    case HMAC_SECRET = 'hmac-secret';
    case APPID_EXCLUDE = 'appidExclude';
    case CRED_PROPS = 'credProps';
    case LARGE_BLOB = 'largeBlob';
    case PAYMENT = 'payment';
}
