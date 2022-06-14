<?php

namespace Laragear\WebAuthn\Attestation\Validator\Pipes;

use Laragear\WebAuthn\SharedPipes\CheckRelyingPartyIdContained as BaseCheckRelyingPartyIdSame;

/**
 * 9. Verify that the value of C.origin matches the Relying Party's origin.
 *
 * @see https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
 *
 * @internal
 */
class CheckRelyingPartyIdContained extends BaseCheckRelyingPartyIdSame
{
    //
}
