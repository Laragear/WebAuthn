<?php

namespace Tests\Http\Requests;

use Illuminate\Auth\Events\Login;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidator;
use Laragear\WebAuthn\ByteBuffer;
use Laragear\WebAuthn\Challenge;
use Laragear\WebAuthn\Http\Requests\AssertedRequest;
use Mockery;
use Ramsey\Uuid\Uuid;
use Tests\DatabaseTestCase;
use Tests\FakeAuthenticator;
use Tests\Stubs\WebAuthnAuthenticatableUser;
use function array_merge;
use function base64_decode;
use function config;
use function now;
use function session;

class AssertedRequestTest extends DatabaseTestCase
{
    protected function defineDatabaseSeeders(): void
    {
        WebAuthnAuthenticatableUser::forceCreate([
            'name' => FakeAuthenticator::ATTESTATION_USER['displayName'],
            'email' => FakeAuthenticator::ATTESTATION_USER['name'],
            'password' => 'test_password',
        ]);

        DB::table('webauthn_credentials')->insert([
            'id' => FakeAuthenticator::CREDENTIAL_ID,
            'authenticatable_type' => WebAuthnAuthenticatableUser::class,
            'authenticatable_id' => 1,
            'user_id' => 'e8af6f703f8042aa91c30cf72289aa07',
            'counter' => 0,
            'rp_id' => 'localhost',
            'origin' => 'http://localhost',
            'aaguid' => Uuid::NIL,
            'attestation_format' => 'none',
            'public_key' => 'eyJpdiI6Imp0U0NVeFNNbW45KzEvMXpad2p2SUE9PSIsInZhbHVlIjoic0VxZ2I1WnlHM2lJakhkWHVkK2kzMWtibk1IN2ZlaExGT01qOElXMDdRTjhnVlR0TDgwOHk1S0xQUy9BQ1JCWHRLNzRtenNsMml1dVQydWtERjFEU0h0bkJGT2RwUXE1M1JCcVpablE2Y2VGV2YvVEE2RGFIRUE5L0x1K0JIQXhLVE1aNVNmN3AxeHdjRUo2V0hwREZSRTJYaThNNnB1VnozMlVXZEVPajhBL3d3ODlkTVN3bW54RTEwSG0ybzRQZFFNNEFrVytUYThub2IvMFRtUlBZamoyZElWKzR1bStZQ1IwU3FXbkYvSm1FU2FlMTFXYUo0SG9kc1BDME9CNUNKeE9IelE5d2dmNFNJRXBKNUdlVzJ3VHUrQWJZRFluK0hib0xvVTdWQ0ZISjZmOWF3by83aVJES1dxbU9Zd1lhRTlLVmhZSUdlWmlBOUFtcTM2ZVBaRWNKNEFSQUhENk5EaC9hN3REdnVFbm16WkRxekRWOXd4cVcvZFdKa2tlWWJqZWlmZnZLS0F1VEVCZEZQcXJkTExiNWRyQmxsZWtaSDRlT3VVS0ZBSXFBRG1JMjRUMnBKRXZxOUFUa2xxMjg2TEplUzdscVo2UytoVU5SdXk1OE1lcFN6aU05ZkVXTkdIM2tKM3Q5bmx1TGtYb1F5bGxxQVR3K3BVUVlia1VybDFKRm9lZDViNzYraGJRdmtUb2FNTEVGZmZYZ3lYRDRiOUVjRnJpcTVvWVExOHJHSTJpMnVBZ3E0TmljbUlKUUtXY2lSWDh1dE5MVDNRUzVRSkQrTjVJUU8rSGhpeFhRRjJvSEdQYjBoVT0iLCJtYWMiOiI5MTdmNWRkZGE5OTEwNzQ3MjhkYWVhYjRlNjk0MWZlMmI5OTQ4YzlmZWI1M2I4OGVkMjE1MjMxNjUwOWRmZTU2IiwidGFnIjoiIn0=',
            'updated_at' => now(),
            'created_at' => now(),
        ]);
    }

    protected function defineEnvironment($app): void
    {
        $app->make('config')->set('auth.providers.users.driver', 'eloquent-webauthn');
        $app->make('config')->set('auth.providers.users.model', WebAuthnAuthenticatableUser::class);
    }

    protected function defineWebRoutes($router): void
    {
        $router->post('test', static function (AssertedRequest $request): void {
            $request->login();
        });
    }

    public function test_verifies_and_logs_in_user(): void
    {
        $this->session(['_webauthn' => new Challenge(
            new ByteBuffer(base64_decode(FakeAuthenticator::ASSERTION_CHALLENGE)), 60, false,
        )]);

        $this->postJson('test', FakeAuthenticator::assertionResponse())->assertOk();

        $this->assertAuthenticatedAs(WebAuthnAuthenticatableUser::find(1));
    }

    public function test_pulls_challenge_session_key(): void
    {
        $this->session(['_webauthn' => new Challenge(
            new ByteBuffer(base64_decode(FakeAuthenticator::ASSERTION_CHALLENGE)), 60, false,
        )]);

        $this->postJson('test', FakeAuthenticator::assertionResponse())->assertOk();

        static::assertNull(session('_webauthn'));
    }

    public function test_logs_in_with_remember_header_x_webauthn_remember(): void
    {
        $event = Event::fake(Login::class);

        $this->session(['_webauthn' => new Challenge(
            new ByteBuffer(base64_decode(FakeAuthenticator::ASSERTION_CHALLENGE)), 60, false,
        )]);

        $this->postJson('test', FakeAuthenticator::assertionResponse(), [
            'X-WebAuthn-Remember' => 1,
        ])->assertOk();

        $event->assertDispatched(Login::class, static function (Login $event): bool {
            return $event->remember;
        });
    }

    public function test_logs_in_with_remember_header_webauthn_remember(): void
    {
        $event = Event::fake(Login::class);

        $this->session(['_webauthn' => new Challenge(
            new ByteBuffer(base64_decode(FakeAuthenticator::ASSERTION_CHALLENGE)), 60, false,
        )]);

        $this->postJson('test', FakeAuthenticator::assertionResponse(), [
            'WebAuthn-Remember' => 1,
        ])->assertOk();

        $event->assertDispatched(Login::class, static function (Login $event): bool {
            return $event->remember;
        });
    }

    public function test_logs_in_with_remember_input(): void
    {
        $event = Event::fake(Login::class);

        $this->session(['_webauthn' => new Challenge(
            new ByteBuffer(base64_decode(FakeAuthenticator::ASSERTION_CHALLENGE)), 60, false,
        )]);

        $this->postJson('test', array_merge(FakeAuthenticator::assertionResponse(), [
            'remember' => 'on',
        ]))->assertOk();

        $event->assertDispatched(Login::class, static function (Login $event): bool {
            return $event->remember;
        });
    }

    public function test_logs_in_with_manual_remember_true(): void
    {
        $event = Event::fake(Login::class);

        $this->session(['_webauthn' => new Challenge(
            new ByteBuffer(base64_decode(FakeAuthenticator::ASSERTION_CHALLENGE)), 60, false,
        )]);

        Route::middleware('web')->post('remember', function (AssertedRequest $request) {
            $request->login(null, true);
        });

        $this->postJson('remember', FakeAuthenticator::assertionResponse())->assertOk();

        $event->assertDispatched(Login::class, static function (Login $event): bool {
            return $event->remember;
        });
    }

    public function test_logs_in_with_manual_remember_false(): void
    {
        $event = Event::fake(Login::class);

        $this->session(['_webauthn' => new Challenge(
            new ByteBuffer(base64_decode(FakeAuthenticator::ASSERTION_CHALLENGE)), 60, false,
        )]);

        Route::middleware('web')->post('remember', function (AssertedRequest $request) {
            $request->login(null, false);
        });

        $this->postJson('remember', FakeAuthenticator::assertionResponse())->assertOk();

        $event->assertDispatched(Login::class, static function (Login $event): bool {
            return ! $event->remember;
        });
    }

    public function test_uses_custom_session_key(): void
    {
        config(['webauthn.challenge.key' => 'foo']);

        $this->session(['foo' => new Challenge(
            new ByteBuffer(base64_decode(FakeAuthenticator::ASSERTION_CHALLENGE)), 60, false,
        )]);

        $this->postJson('test', array_merge(FakeAuthenticator::assertionResponse(), [
            'remember' => 'on',
        ]))->assertOk();

        $this->assertAuthenticatedAs(WebAuthnAuthenticatableUser::find(1));
    }

    public function test_logs_in_with_custom_guard(): void
    {
        $guard = Auth::guard('web');

        Auth::expects('guard')->with('foo')->twice()->andReturn($guard);

        Route::middleware('web')->post('custom', function (AssertedRequest $request) {
            $request->login('foo');
        });

        $this->session(['_webauthn' => new Challenge(
            new ByteBuffer(base64_decode(FakeAuthenticator::ASSERTION_CHALLENGE)), 60, false,
        )]);

        $this->postJson('custom', FakeAuthenticator::assertionResponse())->assertOk();

        $this->assertAuthenticatedAs(WebAuthnAuthenticatableUser::find(1), 'foo');
    }

    public function test_logs_in_returns_user(): void
    {
        Route::middleware('web')->post('custom', function (AssertedRequest $request) {
            static::assertTrue(WebAuthnAuthenticatableUser::find(1)->is($request->login()));
        });

        $this->session(['_webauthn' => new Challenge(
            new ByteBuffer(base64_decode(FakeAuthenticator::ASSERTION_CHALLENGE)), 60, false,
        )]);

        $this->postJson('custom', FakeAuthenticator::assertionResponse())->assertOk();
    }

    public function test_fails_validation_if_a_member_is_missing(): void
    {
        $this->postJson('test', [
            'id' => 'test_id',
            'response' => [
                'authenticatorData' => 'test',
                'clientDataJSON' => 'test',
                'signature' => 'test',
                'userHandle' => 'test',
            ],
            'type' => 'test',
        ])
            ->assertJsonValidationErrorFor('rawId');
    }

    public function test_asserts_with_missing_user_handle(): void
    {
        $response = FakeAuthenticator::assertionResponse();

        Arr::forget($response, 'response.userHandle');

        $this->session(['_webauthn' => new Challenge(
            new ByteBuffer(base64_decode(FakeAuthenticator::ASSERTION_CHALLENGE)), 60, false,
        )]);

        // We know it's going to fail since the user is not in the validation object, this is just for show.
        $this->mock(AssertionValidator::class)
            ->expects('send->thenReturn')
            ->andReturn();

        $this->postJson('test', $response)->assertOk();

        $this->assertAuthenticatedAs(WebAuthnAuthenticatableUser::find(1));
    }

    public function test_destroy_session_on_regeneration(): void
    {
        Route::middleware('web')->post('custom', function (AssertedRequest $request) {
            $request->login(destroySession: true);
        });

        $session = Mockery::mock(\Illuminate\Contracts\Session\Session::class);

        $session->expects('regenerate')->with(true)->andReturn();

        $this->app->resolving(AssertedRequest::class, function (AssertedRequest $request) use ($session): void {
            $request->setLaravelSession($session);
        });

        $this->mock(AssertionValidator::class)
            ->expects('send->thenReturn')
            ->andReturn();

        $this->postJson('custom', FakeAuthenticator::assertionResponse())->assertOk();
    }
}
