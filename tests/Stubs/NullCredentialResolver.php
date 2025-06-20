<?php

namespace Tests\Stubs;

use Closure;
use Illuminate\Database\Eloquent\Builder;

final class NullCredentialResolver
{
    public static function resolveWebAuthnCredentials(): Closure
    {
        return fn (Builder $query) => $query->whereNull('id');
    }
}
