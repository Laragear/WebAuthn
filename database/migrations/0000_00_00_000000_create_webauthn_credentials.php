<?php

use Illuminate\Database\Schema\Blueprint;
use Laragear\WebAuthn\Models\WebAuthnCredential;

return WebAuthnCredential::migration()->with(function (Blueprint $table) {
    // Here you can add custom columns to the Two Factor table.
    //
    // $table->string('alias')->nullable();
});
