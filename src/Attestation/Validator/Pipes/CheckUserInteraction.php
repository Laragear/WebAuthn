<?php

namespace Laragear\WebAuthn\Attestation\Validator\Pipes;

use Laragear\WebAuthn\SharedPipes\CheckUserInteraction as BaseCheckUserInteraction;

/**
 * 14. Verify that the User Present bit of the flags in authData is set.
 *
 * @see https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
 *
 * @internal
 */
class CheckUserInteraction extends BaseCheckUserInteraction
{
    //
}
