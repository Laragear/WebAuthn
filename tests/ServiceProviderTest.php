<?php

namespace Tests;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Fluent;
use Illuminate\Support\ServiceProvider;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use Laragear\WebAuthn\WebAuthnAuthentication;
use Laragear\WebAuthn\WebAuthnServiceProvider;
use Orchestra\Testbench\Attributes\DefineEnvironment;
use function version_compare;

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

    /**
     * @define-env usesCustomTestTime
     */
    #[DefineEnvironment('usesCustomTestTime')]
    public function test_publishes_migrations(): void
    {
        if (version_compare(Application::VERSION, '11', '>=')) {
            $this->markTestSkipped('Laravel handles migration internally');
        }

        static::assertSame(
            [
                realpath(WebAuthnServiceProvider::MIGRATIONS.'/0000_00_00_000000_create_webauthn_credentials.php') => $this->app->databasePath('migrations/2020_01_01_163025_create_webauthn_credentials.php'),
            ],
            ServiceProvider::pathsToPublish(WebAuthnServiceProvider::class, 'migrations')
        );
    }

    protected function usesCustomTestTime()
    {
        $this->travelTo(Carbon::create(2020, 01, 01, 16, 30, 25));
    }

    public function test_bounds_user(): void
    {
        static::assertNull($this->app->make(WebAuthnAuthenticatable::class));

        $user = new class extends Fluent implements WebAuthnAuthenticatable
        {
            use WebAuthnAuthentication;
        };

        $this->app->instance(Authenticatable::class, $user);

        static::assertSame($user, $this->app->make(WebAuthnAuthenticatable::class));
    }
}
