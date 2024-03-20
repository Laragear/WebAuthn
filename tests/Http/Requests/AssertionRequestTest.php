<?php

namespace Tests\Http\Requests;

use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Laragear\WebAuthn\Assertion\Creator\AssertionCreation;
use Laragear\WebAuthn\Assertion\Creator\AssertionCreator;
use Laragear\WebAuthn\Challenge;
use Laragear\WebAuthn\Http\Requests\AssertionRequest;
use Laragear\WebAuthn\JsonTransport;
use Tests\DatabaseTestCase;
use Tests\FakeAuthenticator;
use Tests\Stubs\WebAuthnAuthenticatableUser;
use function config;
use function session;
use function strlen;

class AssertionRequestTest extends DatabaseTestCase
{
    protected function defineDatabaseSeeders(): void
    {
        WebAuthnAuthenticatableUser::forceCreate([
            'name' => FakeAuthenticator::ATTESTATION_USER['displayName'],
            'email' => FakeAuthenticator::ATTESTATION_USER['name'],
            'password' => 'test_password',
        ]);
    }

    protected function defineRoutes($router): void
    {
        $router->middleware('web')->post('test', function (AssertionRequest $request) {
            return $request->toVerify();
        });
    }

    protected function defineEnvironment($app): void
    {
        $app->make('config')->set('auth.providers.users.driver', 'eloquent-webauthn');
        $app->make('config')->set('auth.providers.users.model', WebAuthnAuthenticatableUser::class);
    }

    public function test_creates_assertion(): void
    {
        $this->postJson('test')
            ->assertSessionHas('_webauthn', function (Challenge $challenge): bool {
                return ! $challenge->verify;
            })
            ->assertJson([
                'timeout' => 60000,
                'challenge' => session('_webauthn')->data->toBase64Url(),
            ]);
    }

    public function test_uses_custom_timeout(): void
    {
        config(['webauthn.challenge.timeout' => 120]);

        Route::middleware('web')->post('test', function (AssertionRequest $request) {
            return $request->toVerify();
        });

        $this->postJson('test')
            ->assertJson([
                'timeout' => 120000,
                'challenge' => session('_webauthn')->data->toBase64Url(),
            ]);
    }

    public function test_uses_custom_length(): void
    {
        config(['webauthn.challenge.bytes' => 32]);

        Route::middleware('web')->post('test', function (AssertionRequest $request) {
            return $request->toVerify();
        });

        $this->postJson('test')
            ->assertJson([
                'timeout' => 60000,
                'challenge' => session('_webauthn')->data->toBase64Url(),
            ]);

        static::assertSame(64, strlen(session('_webauthn')->data->toHex()));
    }

    public function test_uses_custom_session_key(): void
    {
        config(['webauthn.challenge.key' => 'foo']);

        Route::middleware('web')->post('test', function (AssertionRequest $request) {
            return $request->toVerify();
        });

        $this->postJson('test')->assertSessionHas('foo');
    }

    public function test_uses_custom_guard(): void
    {
        $guard = Auth::guard('web');

        Auth::partialMock()->expects('guard')->with('foo')->andReturn($guard);

        Route::middleware('web')->post('test', function (AssertionRequest $request) {
            return $request->guard('foo')->toVerify(['email' => FakeAuthenticator::ATTESTATION_USER['name']]);
        });

        $this->postJson('test')
            ->assertOk()
            ->assertJson([
                'timeout' => 60000,
                'challenge' => session('_webauthn')->data->toBase64Url(),
            ]);
    }

    public function test_guard_fails_if_user_not_webauthn_authenticatable(): void
    {
        config(['auth.providers.users.driver' => 'eloquent']);
        config(['auth.providers.users.model' => User::class]);

        Route::middleware('web')->post('test', function (AssertionRequest $request) {
            return $request->guard('web')->toVerify(['email' => FakeAuthenticator::ATTESTATION_USER['name']]);
        });

        $this->postJson('test')
            ->assertStatus(500)
            ->assertSee('The user found for the [web] auth guard is not an instance of [WebAuthnAuthenticatable].');
    }

    public function test_uses_fast_login(): void
    {
        Route::middleware('web')->post('test', function (AssertionRequest $request) {
            return $request->fastLogin()->toVerify();
        });

        $this->postJson('test')->assertJson([
            'timeout' => 60000,
            'userVerification' => 'discouraged',
            'challenge' => session('_webauthn')->data->toBase64Url(),
        ]);

        static::assertFalse(session('_webauthn')->verify);
    }

    public function test_uses_secure_login(): void
    {
        Route::middleware('web')->post('test', function (AssertionRequest $request) {
            return $request->secureLogin()->toVerify();
        });

        $this->postJson('test')->assertJson([
            'timeout' => 60000,
            'userVerification' => 'required',
            'challenge' => session('_webauthn')->data->toBase64Url(),
        ]);

        static::assertTrue(session('_webauthn')->verify);
    }

    public function test_uses_verify_with_already_instanced_user(): void
    {
        Route::middleware('web')->post('test', function (AssertionRequest $request) {
            return $request->toVerify(WebAuthnAuthenticatableUser::find(1));
        });

        $creator = $this->mock(AssertionCreator::class);

        $creator->expects('send')->withArgs(function (AssertionCreation $creation): bool {
            return $creation->user->getKey() === 1;
        })
            ->andReturnSelf();

        $creator->expects('then')->andReturn(new JsonTransport());

        $this->postJson('test')->assertOk();
    }

    public function test_uses_verify_with_user_id(): void
    {
        Route::middleware('web')->post('test', function (AssertionRequest $request) {
            return $request->toVerify(1);
        });

        $creator = $this->mock(AssertionCreator::class);

        $creator->expects('send')->withArgs(function (AssertionCreation $creation): bool {
            return $creation->user->getKey() === 1;
        })
            ->andReturnSelf();

        $creator->expects('then')->andReturn(new JsonTransport());

        $this->postJson('test')->assertOk();
    }

    public function test_uses_verify_with_bad_id_returning_null_user(): void
    {
        Route::middleware('web')->post('test', function (AssertionRequest $request) {
            return $request->toVerify(99);
        });

        $creator = $this->mock(AssertionCreator::class);

        $creator->expects('send')->withArgs(function (AssertionCreation $creation): bool {
            return ! $creation->user;
        })
            ->andReturnSelf();

        $creator->expects('then')->andReturn(new JsonTransport());

        $this->postJson('test')->assertOk();
    }

    public function test_uses_verify_with_bad_credentials_returning_null_user(): void
    {
        Route::middleware('web')->post('test', function (AssertionRequest $request) {
            return $request->toVerify(['email' => 'invalid@email.com']);
        });

        $creator = $this->mock(AssertionCreator::class);

        $creator->expects('send')->withArgs(function (AssertionCreation $creation): bool {
            return ! $creation->user;
        })
            ->andReturnSelf();

        $creator->expects('then')->andReturn(new JsonTransport());

        $this->postJson('test')->assertOk();
    }
}
