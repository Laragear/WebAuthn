<?php

namespace Tests;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Fluent;
use Illuminate\Support\ServiceProvider;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use Laragear\WebAuthn\WebAuthnAuthentication;
use Laragear\WebAuthn\WebAuthnServiceProvider;

class ServiceProviderTest extends TestCase
{
    public function test_merges_config(): void
    {
        static::assertSame(
            File::getRequire(WebAuthnServiceProvider::CONFIG),
            $this->app->make('config')->get('webauthn')
        );
    }

    public function test_publishes_config(): void
    {
        static::assertSame(
            [WebAuthnServiceProvider::CONFIG => $this->app->configPath('webauthn.php')],
            ServiceProvider::$publishGroups['config']
        );
    }

    public function test_publishes_migrations(): void
    {
        $format = now()->format('Y_m_d_His');

        static::assertSame(
            [
                realpath(WebAuthnServiceProvider::MIGRATIONS . '/2022_07_01_000000_create_webauthn_credentials.php') =>
                    $this->app->databasePath("migrations/{$format}_create_webauthn_credentials.php"),
            ],
            ServiceProvider::pathsToPublish(WebAuthnServiceProvider::class, 'migrations')
        );
    }

    public function test_bounds_user(): void
    {
        static::assertNull($this->app->make(WebAuthnAuthenticatable::class));

        $user = new class extends Fluent implements WebAuthnAuthenticatable {
            use WebAuthnAuthentication;
        };

        $this->app->instance(Authenticatable::class, $user);

        static::assertSame($user, $this->app->make(WebAuthnAuthenticatable::class));
    }

    public function test_publishes_routes_file(): void
    {
        static::assertSame(
            [WebAuthnServiceProvider::ROUTES => $this->app->basePath('routes/webauthn.php')],
            ServiceProvider::$publishGroups['routes']
        );
    }
}
