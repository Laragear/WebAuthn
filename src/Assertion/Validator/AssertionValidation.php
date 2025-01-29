<?php

namespace Laragear\WebAuthn\Assertion\Validator;

use Illuminate\Http\Request;
use Laragear\WebAuthn\Attestation\AuthenticatorData;
use Laragear\WebAuthn\Challenge\Challenge;
use Laragear\WebAuthn\ClientDataJson;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use Laragear\WebAuthn\JsonTransport;
use Laragear\WebAuthn\Models\WebAuthnCredential;

class AssertionValidation
{
    /**
     * Keys that should be extracted from the Assertion Validation Request.
     *
     * @const array
     */
    public const REQUEST_KEYS = [
        'id', 'rawId', 'response', 'type', 'clientExtensionResults', 'authenticatorAttachment',
    ];

    /**
     * Create a new Assertion Validation instance.
     */
    public function __construct(
        public JsonTransport $json,
        public ?WebAuthnAuthenticatable $user = null,
        public ?Challenge $challenge = null,
        public ?WebAuthnCredential $credential = null,
        public ?ClientDataJson $clientDataJson = null,
        public ?AuthenticatorData $authenticatorData = null,
    ) {
        //
    }

    /**
     * Create a new Assertion Validation instance from a WebAuthn request data.
     */
    public static function fromRequest(?Request $request = null): static
    {
        // @phpstan-ignore-next-line
        return new static(new JsonTransport(($request ?? app('request'))->only(static::REQUEST_KEYS)));
    }
}
