<?php

namespace Laragear\WebAuthn\Enums;

/**
 * @see https://www.iana.org/assignments/webauthn/webauthn.xhtml
 * @see https://www.w3.org/TR/webauthn-2/#sctn-extensions
 */
enum Extension: string
{
    case Appid = 'appid';
    case TxAuthSimple = 'txAuthSimple';
    case TxAuthGeneric = 'txAuthGeneric';
    case AuthnSel = 'authnSel';
    case Exts = 'exts';
    case Uvi = 'uvi';
    case Loc = 'loc';
    case Uvm = 'uvm';
    case CredProtect = 'credProtect';
    case CredBlob = 'credBlob';
    case LargeBlobKey = 'largeBlobKey';
    case MinPinLength = 'minPinLength';
    case HmacSecret = 'hmac-secret';
    case AppidExclude = 'appidExclude';
    case CredProps = 'credProps';
    case LargeBlob = 'largeBlob';
    case Payment = 'payment';
}
