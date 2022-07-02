<?php

namespace Laragear\WebAuthn;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use function Safe\preg_replace;

/**
 * @internal
 */
class WebAuthnServiceProvider extends ServiceProvider
{
    public const ROUTES = __DIR__.'/../routes/webauthn.php';
    public const CONTROLLERS = __DIR__.'/../stubs/controllers';
    public const CONFIG = __DIR__.'/../config/webauthn.php';
    public const MIGRATIONS = __DIR__.'/../database/migrations';
    public const JS = __DIR__.'/../resources/js';

    /**
     * Register the service provider.
     *
     * @return void
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function register(): void
    {
        $this->mergeConfigFrom(static::CONFIG, 'webauthn');

        $this->registerUser();

        $this->registerUserProvider();
    }

    /**
     * Boot the service provider.
     *
     * @return void
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishesMigrations(static::MIGRATIONS);
            $this->publishes([static::ROUTES => $this->app->basePath('routes/webauthn.php')], 'routes');
            $this->publishes([static::CONTROLLERS => $this->app->path('Http/Controllers/WebAuthn')], 'controllers');
            $this->publishes([static::JS => $this->app->resourcePath('js/vendor/webauthn')], 'js');
        }
    }

    /**
     * Publishes migrations from the given path.
     *
     * @param  array|string  $paths
     * @param  string  $groups
     * @return void
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function publishesMigrations(array|string $paths, string $groups = 'migrations'): void
    {
        $prefix = now()->format('Y_m_d_His');

        $files = [];

        foreach ($this->app->make('files')->files($paths) as $file) {
            $filename = preg_replace('/^[\d|_]+/', '', $file->getFilename());

            $files[$file->getRealPath()] = $this->app->databasePath("migrations/{$prefix}_$filename");
        }

        $this->publishes($files, $groups);
    }

    /**
     * Registers the Web Authenticatable User.
     *
     * @return void
     */
    protected function registerUser(): void
    {
        $this->app->bind(
            Contracts\WebAuthnAuthenticatable::class,
            static function (Application $app): ?Contracts\WebAuthnAuthenticatable {
                $user = $app->make(AuthenticatableContract::class);

                return $user instanceof WebAuthnAuthenticatable ? $user : null;
            }
        );
    }

    /**
     * Extends the Authentication Factory with a WebAuthn Eloquent-Compatible User Provider.
     *
     * @return void
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function registerUserProvider(): void
    {
        $this->callAfterResolving('auth', static function (AuthManager $auth): void {
            $auth->provider(
                'eloquent-webauthn',
                static function (Application $app, array $config): Auth\WebAuthnUserProvider {
                    return new Auth\WebAuthnUserProvider(
                        $app->make('hash'),
                        $config['model'],
                        $app->make(Assertion\Validator\AssertionValidator::class),
                        $config['password_fallback'] ?? true,
                    );
                }
            );
        });
    }
}
