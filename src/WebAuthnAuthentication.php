<?php

namespace Laragear\WebAuthn;

use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use Illuminate\Support\Facades\Date;
use JetBrains\PhpStorm\ArrayShape;
use Laragear\WebAuthn\Models\WebAuthnCredential;
use function in_array;

/**
 * @property-read \Illuminate\Database\Eloquent\Collection<int, \Laragear\WebAuthn\Models\WebAuthnCredential> $webAuthnCredentials
 *
 * @see \Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable
 * @see \Laragear\WebAuthn\Models\WebAuthnCredential
 */
trait WebAuthnAuthentication
{
    /**
     * Returns displayable data to be used to create WebAuthn Credentials.
     *
     * @return array{name: string, displayName: string}
     */
    #[ArrayShape(['name' => "string", 'displayName' => "string"])]
    public function webAuthnData(): array
    {
        return [
            'name' => $this->email,
            'displayName' => $this->name,
        ];
    }

    /**
     * Removes all credentials previously registered.
     *
     * @param  string  ...$except
     * @return void
     */
    public function flushCredentials(string ...$except): void
    {
        if ($this->relationLoaded('webAuthnCredentials') && $this->webAuthnCredentials instanceof Collection) {
            $partitioned = $this->webAuthnCredentials
                ->partition(static function (WebAuthnCredential $credential) use ($except): bool {
                    return in_array($credential->getKey(), $except, true);
                });

            $partitioned->first()->each->delete();

            $this->setRelation('webAuthnCredentials', $partitioned->last());

            return;
        }

        $this->webAuthnCredentials()->whereKeyNot($except)->delete();
    }

    /**
     * Disables all credentials for the user.
     *
     * @param  string  ...$except
     * @return void
     */
    public function disableAllCredentials(string ...$except): void
    {
        if ($this->relationLoaded('webAuthnCredentials') && $this->webAuthnCredentials instanceof Collection) {
            $this->webAuthnCredentials
                ->each(static function (WebAuthnCredential $credential) use ($except): bool {
                    if ($credential->isEnabled() && in_array($credential->getKey(), $except, true)) {
                        $credential->disable();
                    }
                });
        } else {
            $this->webAuthnCredentials()->whereKeyNot($except)->update(['disabled_at' => Date::now()]);
        }
    }

    /**
     * Makes an instance of a WebAuthn Credential attached to this user.
     *
     * @param  array  $properties
     * @return \Laragear\WebAuthn\Models\WebAuthnCredential
     */
    public function makeWebAuthnCredential(array $properties): Models\WebAuthnCredential
    {
        return $this->webAuthnCredentials()->make()->forceFill($properties);
    }

    /**
     * Returns a queryable relationship for its WebAuthn Credentials.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany&\Laragear\WebAuthn\Models\WebAuthnCredential
     */
    public function webAuthnCredentials(): MorphMany
    {
        return $this->morphMany(Models\WebAuthnCredential::class, 'authenticatable');
    }
}
