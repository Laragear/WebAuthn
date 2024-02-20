<?php

namespace Laragear\WebAuthn\Attestation\Validator\Pipes;

use Closure;
use Illuminate\Contracts\Config\Repository;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidation;
use Laragear\WebAuthn\Exceptions\AttestationException;
use Laragear\WebAuthn\Exceptions\DataException;
use Ramsey\Uuid\Uuid;
use function parse_url;
use const PHP_URL_HOST;

/**
 * @internal
 */
class MakeWebAuthnCredential
{
    /**
     * Create a new pipe instance.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(protected Repository $config)
    {
        //
    }

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
        $validation->credential = $validation->user->makeWebAuthnCredential([
            'id' => $validation->request->json('id'),

            'user_id' => $validation->challenge->properties['user_uuid'],
            'alias' => $validation->request->json('response.alias'),

            'counter' => $validation->attestationObject->authenticatorData->counter,
            'rp_id' => $this->config->get('webauthn.relying_party.id') ?? parse_url($this->config->get('app.url'), PHP_URL_HOST),
            'origin' => $validation->clientDataJson->origin,
            'transports' => $validation->request->json('response.transports'),
            'aaguid' => Uuid::fromBytes($validation->attestationObject->authenticatorData->attestedCredentialData->aaguid),

            'public_key' => $this->getPublicKeyAsPem($validation),
            'attestation_format' => $validation->attestationObject->formatName,
        ]);

        return $next($validation);
    }

    /**
     * Returns a public key from the credentials as a PEM string.
     *
     * @param  \Laragear\WebAuthn\Attestation\Validator\AttestationValidation  $validation
     * @return string
     */
    protected function getPublicKeyAsPem(AttestationValidation $validation): string
    {
        try {
            return $validation->attestationObject->authenticatorData->getPublicKeyPem();
        } catch (DataException $e) {
            throw AttestationException::make($e->getMessage());
        }
    }
}
