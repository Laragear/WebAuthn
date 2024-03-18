<?php

namespace Tests;

use Orchestra\Testbench\Attributes\WithMigration;

#[WithMigration]
class DatabaseTestCase extends TestCase
{
    protected function defineDatabaseMigrations(): void
    {
        $this->loadLaravelMigrations();
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
    }
}
