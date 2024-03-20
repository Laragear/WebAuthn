<?php

namespace Tests;

use Illuminate\Contracts\Session\Session as SessionContract;
use Laragear\WebAuthn\Challenge;
use Laragear\WebAuthn\ChallengeRepository;
use Laragear\WebAuthn\Enums\UserVerification;
use Mockery\MockInterface;

use function now;

class ChallengeRepositoryTest extends TestCase
{
    public function test_stores_challenge(): void
    {
        $this->mock(SessionContract::class)
            ->expects('put')
            ->withArgs(function (string $key, Challenge $challenge): bool {
                static::assertSame('_webauthn', $key);
                static::assertSame(60, $challenge->timeout);
                static::assertSame([], $challenge->properties);
                static::assertSame(now()->addMinute()->getTimestamp(), $challenge->expiresAt);
                static::assertFalse($challenge->verify);

                return true;
            });

        $this->app->make(ChallengeRepository::class)->store(null, []);
    }

    public function test_stores_challenge_with_options(): void
    {
        $this->mock(SessionContract::class)
            ->expects('put')
            ->withArgs(function (string $key, Challenge $challenge): bool {
                return '_webauthn' === $key
                    && ['foo' => 'bar'] === $challenge->properties;
            });

        $this->app->make(ChallengeRepository::class)->store(null, ['foo' => 'bar']);
    }

    public function test_stores_challenge_with_user_verification_required(): void
    {
        $this->mock(SessionContract::class, function (MockInterface $session): void {
            $session->expects('put')->withArgs(function (string $key, Challenge $challenge): bool {
                return '_webauthn' === $key
                    && $challenge->verify === true;
            });
        });

        $this->app->make(ChallengeRepository::class)->store(UserVerification::REQUIRED, ['foo' => 'bar']);
    }

    public function test_stores_challenge_with_user_verification_not_required(): void
    {
        $this->mock(SessionContract::class)
            ->expects('put')
            ->withArgs(function (string $key, Challenge $challenge): bool {
                return '_webauthn' === $key
                    && $challenge->verify === false;
            });

        $this->app->make(ChallengeRepository::class)->store(UserVerification::PREFERRED, ['foo' => 'bar']);
    }

    public function test_pulls_valid_challenge(): void
    {
        $challenge = Challenge::random(60, 60);

        $this->mock(SessionContract::class)
            ->expects('pull')
            ->with('_webauthn')
            ->andReturn($challenge);

        static::assertSame($challenge, $this->app->make(ChallengeRepository::class)->pull());
    }

    public function test_pulls_doesnt_return_non_existent_challenge(): void
    {
        $challenge = Challenge::random(60, -60);

        $this->mock(SessionContract::class)
            ->expects('pull')
            ->with('_webauthn')
            ->andReturn($challenge);

        static::assertNull($this->app->make(ChallengeRepository::class)->pull());
    }

    public function test_pulls_doesnt_return_expired_challenge(): void
    {
        $this->mock(SessionContract::class)
            ->expects('pull')
            ->with('_webauthn')
            ->andReturnNull();

        static::assertNull($this->app->make(ChallengeRepository::class)->pull());
    }
}
