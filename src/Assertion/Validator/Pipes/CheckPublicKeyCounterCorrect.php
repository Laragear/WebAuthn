<?php

namespace Laragear\WebAuthn\Assertion\Validator\Pipes;

use Closure;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Events\CredentialCloned;
use Laragear\WebAuthn\Exceptions\AssertionException;

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
class CheckPublicKeyCounterCorrect
{
    /**
     * Handle the incoming Assertion Validation.
     *
     * @throws \Laragear\WebAuthn\Exceptions\AssertionException
     */
    public function handle(AssertionValidation $validation, Closure $next): mixed
    {
        if ($this->hasCounter($validation) && $this->counterBelowStoredCredential($validation)) {
            $validation->credential->disable();

            CredentialCloned::dispatch($validation->credential, $validation->authenticatorData->counter);

            throw AssertionException::make('Credential counter not over stored counter.');
        }

        return $next($validation);
    }

    /**
     * Check if the incoming credential or the stored credential have a counter.
     */
    protected function hasCounter(AssertionValidation $validation): bool
    {
        return $validation->credential->counter
            || $validation->authenticatorData->counter;
    }

    /**
     * Check if the credential counter is equal or higher than what the authenticator reports.
     */
    protected function counterBelowStoredCredential(AssertionValidation $validation): bool
    {
        return $validation->authenticatorData->counter <= $validation->credential->counter;
    }
}
