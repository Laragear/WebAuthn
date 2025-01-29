<?php

namespace Laragear\WebAuthn\Attestation\Validator;

use Illuminate\Http\Request;
use Laragear\WebAuthn\Attestation\AttestationObject;
use Laragear\WebAuthn\Challenge\Challenge;
use Laragear\WebAuthn\ClientDataJson;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use Laragear\WebAuthn\JsonTransport;
use Laragear\WebAuthn\Models\WebAuthnCredential;

class AttestationValidation
{
    /**
     * Keys that should be extracted from the Attestation Validation Request.
     *
     * @const array
     */
    public const REQUEST_KEYS = [
        'id', 'rawId', 'response', 'type', 'origin', 'challenge', 'clientExtensionResults', 'authenticatorAttachment',
    ];

    /**
     * Create a new Attestation Validation procedure.
     */
    public function __construct(
        public ?WebAuthnAuthenticatable $user,
        public JsonTransport $json,
        public ?Challenge $challenge = null,
        public ?AttestationObject $attestationObject = null,
        public ?ClientDataJson $clientDataJson = null,
        public ?WebAuthnCredential $credential = null,
    ) {
        //
    }

    /**
     * Create a new Attestation Creation instance from a request and a user.
     */
    public static function fromRequest(?Request $request = null, ?WebAuthnAuthenticatable $user = null): static
    {
        // @phpstan-ignore-next-line
        return new static($user, new JsonTransport(($request ?? app('request'))->only(static::REQUEST_KEYS)));
    }
}
