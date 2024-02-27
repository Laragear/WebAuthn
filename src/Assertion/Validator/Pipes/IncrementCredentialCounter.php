<?php

namespace Laragear\WebAuthn\Assertion\Validator\Pipes;

use Closure;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;

/**
 * 21. Let storedSignCount be the stored signature counter value associated with credential.id.
 *     If authData.signCount is nonzero or storedSignCount is nonzero, then run the following sub-step:
 *
 *     - If authData.signCount
 *         -> is greater than storedSignCount:
 *             Update storedSignCount to be the value of authData.signCount.
 *         -> less than or equal to storedSignCount:
 *             This is a signal that the authenticator may be cloned, i.e. at least two copies of the
 *             credential private key may exist and are being used in parallel. Relying Parties
 *             should incorporate this information into their risk scoring. Whether the Relying
 *             Party updates storedSignCount in this case, or not, or fails the authentication
 *             ceremony or not, is Relying Party-specific.
 *
 * @internal
 */
class IncrementCredentialCounter
{
    /**
     * Handle the incoming Assertion Validation.
     */
    public function handle(AssertionValidation $validation, Closure $next): mixed
    {
        $validation->credential->syncCounter($validation->authenticatorData->counter);

        return $next($validation);
    }
}
