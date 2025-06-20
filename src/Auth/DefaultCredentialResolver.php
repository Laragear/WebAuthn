<?php

namespace Laragear\WebAuthn\Auth;

use Closure;
use Illuminate\Contracts\Database\Eloquent\Builder;

class DefaultCredentialResolver
{
    public static function resolveWebAuthnCredentials(string $keyId): Closure
    {
        return static function (Builder $query) use ($keyId): void {
            $query->whereHas('webAuthnCredentials', static function (Builder $query) use ($keyId): void {
                // @phpstan-ignore-next-line
                $query->whereKey($keyId)->whereEnabled();
            });
        };
    }
}
