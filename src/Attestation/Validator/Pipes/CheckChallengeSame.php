<?php

namespace Laragear\WebAuthn\Attestation\Validator\Pipes;

use Laragear\WebAuthn\SharedPipes\CheckChallengeSame as BaseCheckChallengeSame;

/**
 * 8. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
 *
 * @see https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential
 *
 * @internal
 */
class CheckChallengeSame extends BaseCheckChallengeSame
{
    //
}
