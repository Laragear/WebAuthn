<?php

namespace Laragear\WebAuthn\Http\Requests;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Foundation\Http\FormRequest;
use Laragear\WebAuthn\Attestation\Creator\AttestationCreation;
use Laragear\WebAuthn\Attestation\Creator\AttestationCreator;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use Laragear\WebAuthn\Enums\ResidentKey;
use Laragear\WebAuthn\Enums\UserVerification;

/**
 * @method \Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable user($guard = null)
 */
class AttestationRequest extends FormRequest
{
    /**
     * The attestation instance that would be returned.
     */
    protected AttestationCreation $attestation;

    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(?WebAuthnAuthenticatable $user): bool
    {
        return (bool) $user;
    }

    /**
     * Returns the existing attestation instance.
     */
    protected function attestation(): AttestationCreation
    {
        return $this->attestation ??= new AttestationCreation($this->user(), $this);
    }

    /**
     * Makes the authenticator to only check for user presence on registration.
     *
     * @return $this
     */
    public function fastRegistration(): static
    {
        $this->attestation()->userVerification = UserVerification::DISCOURAGED;

        return $this;
    }

    /**
     * Makes the authenticator to always verify the user thoroughly on registration.
     *
     * @return $this
     */
    public function secureRegistration(): static
    {
        $this->attestation()->userVerification = UserVerification::REQUIRED;

        return $this;
    }

    /**
     * Tells the authenticator use this credential to login instantly, instead of asking for one.
     *
     * @return $this
     */
    public function userless(): static
    {
        $this->attestation()->residentKey = ResidentKey::REQUIRED;

        return $this;
    }

    /**
     * Allows the device to create multiple credentials for the same user for this app.
     *
     * @return $this
     */
    public function allowDuplicates(): static
    {
        $this->attestation()->uniqueCredentials = false;

        return $this;
    }

    /**
     * Returns a response with the instructions to create a WebAuthn Credential.
     */
    public function toCreate(): Responsable
    {
        return $this->container
            ->make(AttestationCreator::class)
            ->send($this->attestation())
            ->then(static function (AttestationCreation $creation): Responsable {
                return $creation->json;
            });
    }
}
