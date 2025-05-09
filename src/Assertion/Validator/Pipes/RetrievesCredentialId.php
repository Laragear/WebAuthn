<?php

namespace Laragear\WebAuthn\Assertion\Validator\Pipes;

use Closure;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Exceptions\AssertionException;
use Laragear\WebAuthn\Models\WebAuthnCredential;

use function in_array;

/**
 * @internal
 */
class RetrievesCredentialId
{
    /**
     * Handle the incoming Assertion Validation.
     *
     * @throws \Laragear\WebAuthn\Exceptions\AssertionException
     */
    public function handle(AssertionValidation $validation, Closure $next): mixed
    {
        $id = $validation->json->get('id');

        // First, always check if the credential is on the list of accepted credentials IDs
        // before going to the database to retrieve the complete credential in question.
        if ($this->credentialNotInChallenge($id, $validation->challenge->properties)) {
            throw AssertionException::make('Credential is not on accepted list.');
        }

        // We can now find the credential.
        $validation->credential = WebAuthnCredential::whereKey($id)->first(); // @phpstan-ignore-line

        if (! $validation->credential) {
            throw AssertionException::make('Credential ID does not exist.');
        }

        if ($validation->credential->isDisabled()) {
            throw AssertionException::make('Credential ID is blacklisted.');
        }

        return $next($validation);
    }

    /**
     * Check if the previous Assertion request specified a credentials list to accept.
     */
    protected function credentialNotInChallenge(string $id, array $properties): bool
    {
        return isset($properties['credentials']) && ! in_array($id, $properties['credentials'], true);
    }
}
