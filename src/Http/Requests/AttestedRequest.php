<?php

namespace Laragear\WebAuthn\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use JetBrains\PhpStorm\ArrayShape;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidation;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidator;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use Laragear\WebAuthn\Events\CredentialCreated;
use Laragear\WebAuthn\Models\WebAuthnCredential;
use function is_callable;

/**
 * @method \Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable user($guard = null)
 */
class AttestedRequest extends FormRequest
{
    /**
     * The new credential instance.
     *
     * @var \Laragear\WebAuthn\Models\WebAuthnCredential
     */
    protected WebAuthnCredential $credential;

    /**
     * Determine if the user is authorized to make this request.
     *
     * @param  \Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable|null  $user
     * @return bool
     */
    public function authorize(?WebAuthnAuthenticatable $user): bool
    {
        return $user !== null;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array
     */
    #[ArrayShape([
        'id' => "string", 'rawId' => "string", 'response' => "string", 'response.clientDataJSON' => "string",
        'response.attestationObject' => "string", 'type' => "string"
    ])]
    public function rules(): array
    {
        return [
            'id' => 'required|string',
            'rawId' => 'required|string',
            'response' => 'required|array',
            'response.clientDataJSON' => 'required|string',
            'response.attestationObject' => 'required|string',
            'type' => 'required|string',
        ];
    }

    /**
     * Handle a passed validation attempt.
     *
     * @return void
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function passedValidation(): void
    {
        $this->credential = $this->container->make(AttestationValidator::class)
            // @phpstan-ignore-next-line
            ->send(new AttestationValidation($this->user(), $this))
            ->then(static function (AttestationValidation $validation): WebAuthnCredential {
                return $validation->credential;
            });
    }

    /**
     * Save and return the generated WebAuthn Credentials.
     *
     * @param  array|callable  $saving
     * @return string
     */
    public function save(array|callable $saving = []): string
    {
        is_callable($saving) ? $saving($this->credential) : $this->credential->forceFill($saving);

        $this->credential->save();

        // @phpstan-ignore-next-line
        CredentialCreated::dispatch($this->user(), $this->credential);

        return $this->credential->getKey();
    }
}
