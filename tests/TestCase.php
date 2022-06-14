<?php

namespace Tests;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Laragear\WebAuthn\WebAuthnServiceProvider;
use Orchestra\Testbench\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    use RefreshDatabase;

    protected function defineDatabaseMigrations(): void
    {
        $this->loadLaravelMigrations();
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
    }

    protected function getPackageProviders($app): array
    {
        return [WebAuthnServiceProvider::class];
    }
}
