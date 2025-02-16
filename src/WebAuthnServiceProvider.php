<?php

namespace Laragear\WebAuthn;

use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Authenticatable as AuthenticatableContract;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Laragear\WebAuthn\Challenge\SessionChallengeRepository;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;

/**
 * @internal
 */
class WebAuthnServiceProvider extends ServiceProvider
{
    public const CONTROLLERS = __DIR__.'/../stubs/controllers';
    public const CONFIG = __DIR__.'/../config/webauthn.php';
    public const MIGRATIONS = __DIR__.'/../database/migrations';
    public const JS = __DIR__.'/../resources/js';

    /**
     * Register the service provider.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function register(): void
    {
        $this->mergeConfigFrom(static::CONFIG, 'webauthn');

        $this->registerUser();

        $this->registerUserProvider();

        $this->registerChallengeRepository();
    }

    /**
     * Boot the service provider.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function boot(): void
    {
        $this->commands(Console\WebAuthnInstallCommand::class);

        if ($this->app->runningInConsole()) {
            $this->publishesPackageMigrations(static::MIGRATIONS);
            $this->publishes([static::CONFIG => $this->app->configPath('webauthn.php')], 'config');
            // @phpstan-ignore-next-line
            $this->publishes([static::CONTROLLERS => $this->app->path('Http/Controllers/WebAuthn')], 'controllers');
            $this->publishes([static::JS => $this->app->resourcePath('js/vendor/webauthn')], 'js');
        }
    }

    /**
     * Publishes migrations from the given path.
     *
     * @param  string[]|string  $paths
     */
    protected function publishesPackageMigrations(array|string $paths): void
    {
        foreach ((array) $paths as $path) {
            $this->publishesMigrations([$path => $this->app->databasePath('migrations/')], 'migrations');
        }
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
     *
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

    /**
     * Register the default challenge repository.
     */
    protected function registerChallengeRepository(): void
    {
        $this->app->bindIf(
            Contracts\WebAuthnChallengeRepository::class,
            static function (Application $app): Contracts\WebAuthnChallengeRepository {
                return $app->make(SessionChallengeRepository::class);
            }
        );
    }
}
