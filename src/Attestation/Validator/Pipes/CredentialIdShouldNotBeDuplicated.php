<?php

namespace Laragear\WebAuthn\Attestation\Validator\Pipes;

use Closure;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidation;
use Laragear\WebAuthn\Exceptions\AttestationException;
use Laragear\WebAuthn\Models\WebAuthnCredential;

/**
 * @internal
 */
class CredentialIdShouldNotBeDuplicated
{
    /**
     * Handle the incoming Attestation Validation.
     *
     * @param  \Laragear\WebAuthn\Attestation\Validator\AttestationValidation  $validation
     * @param  \Closure  $next
     * @return mixed
     * @throws \Laragear\WebAuthn\Exceptions\AttestationException
     */
    public function handle(AttestationValidation $validation, Closure $next): mixed
    {
        if ($this->credentialAlreadyExists($validation)) {
            throw AttestationException::make('Credential ID already exists in the database.');
        }

        return $next($validation);
    }

    /**
     * Finds a WebAuthn Credential by the issued ID.
     *
     * @param  \Laragear\WebAuthn\Attestation\Validator\AttestationValidation  $validation
     * @return bool
     */
    protected function credentialAlreadyExists(AttestationValidation $validation): bool
    {
        return WebAuthnCredential::whereKey($validation->request->json('id'))->exists();
    }
}
