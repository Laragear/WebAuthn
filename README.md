# WebAuthn

[![Latest Version on Packagist](https://img.shields.io/packagist/v/laragear/webauthn.svg)](https://packagist.org/packages/laragear/webauthn)
[![Latest stable test run](https://github.com/Laragear/WebAuthn/actions/workflows/php.yml/badge.svg?branch=1.x)](https://github.com/Laragear/WebAuthn/actions/workflows/php.yml)
[![Coverage](https://codecov.io/gh/Laragear/WebAuthn/graph/badge.svg?token=HIngrvQeOj)](https://codecov.io/gh/Laragear/WebAuthn)
[![Maintainability](https://qlty.sh/badges/9dea0798-e355-4d97-b959-da9ae2c792aa/maintainability.svg)](https://qlty.sh/gh/Laragear/projects/WebAuthn)
[![Sonarcloud Status](https://sonarcloud.io/api/project_badges/measure?project=Laragear_WebAuthn&metric=alert_status)](https://sonarcloud.io/dashboard?id=Laragear_WebAuthn)
[![Laravel Octane Compatibility](https://img.shields.io/badge/Laravel%20Octane-Compatible-success?style=flat&logo=laravel)](https://laravel.com/docs/11.x/octane#introduction)

Authenticate users with Passkeys: fingerprints, patterns and biometric data.

```php
// App\Http\Controllers\LoginController.php
use Laragear\WebAuthn\Http\Requests\AssertedRequest;

public function login(AssertedRequest $request)
{
    $user = $request->login();

    return response()->json(['message' => "Welcome back, $user->name!"]);
}
```
> [!TIP]
>
> You want to add two-factor authentication to your app? Check out [Laragear TwoFactor](https://github.com/Laragear/TwoFactor).

## Become a sponsor

[![](.github/assets/support.png)](https://github.com/sponsors/DarkGhostHunter)

Your support allows me to keep this package free, up-to-date and maintainable. Alternatively, you can **spread the word on social media!**

## Requirements

* Laravel 11.x or later.
* The `ext-openssl` extension.
* The `ext-sodium` extension (optional, for EdDSA 25519 public keys).

> [!TIP]
> 
> If you can't enable the `ext-sodium` extension for whatever reason, you may try installing [`paragonie/sodium_compat`](https://github.com/paragonie/sodium_compat).

## Installation

Require this package into your project using Composer:

```bash
composer require laragear/webauthn
```

## How Passkeys work?

Passkeys, hence WebAuthn, consists in two _ceremonies_: attestation, and assertion.

Attestation is the process of asking the authenticator (a phone, laptop, USB key...) to create a private-public key pair, save the private key internally, and **store** the public key inside your app. For that to work, the browser must support WebAuthn, which is what intermediates between the authenticator (OS & device hardware) and the server.

Assertion is the process of pushing a cryptographic challenge to the authenticator, which will return back to the server _signed_ by the private key of the device. Upon arrival, the server checks the signature is correct with the stored public key, ready to **log in**.

The private key doesn't leave the authenticator, there are no shared passwords stored anywhere, and Passkeys only work on the server domain (like google.com) or subdomain (like auth.google.com).

## Set up

We need to make sure your users can register their devices and authenticate with them.

1. [Publish the files](#2-publish-files-and-migrate)
2. [Add the WebAuthn driver](#1-add-the-webauthn-driver)
3. [Implement the contract and trait](#3-implement-the-contract-and-trait)
4. [Register the controllers](#4-register-the-routes-and-controllers) _(optional)_
5. [Use the Javascript helper](#5-use-the-javascript-helper) _(optional)_

### 1. Add the WebAuthn driver

Laragear WebAuthn works by extending the Eloquent User Provider with a simple additional check to find a user for the given WebAuthn Credentials (Assertion). This makes this WebAuthn package compatible with any guard you may have.

Simply go into your `auth.php` configuration file, change the driver from `eloquent` to `eloquent-webauthn`, and add the `password_fallback` to `true`.

```php
return [
    // ...

    'providers' => [
        'users' => [
            'driver' => 'eloquent-webauthn',
            'model' => App\User::class,
            'password_fallback' => true,
        ],
    ]
];
```

The `password_fallback` indicates the User Provider should fall back to validate the password when the request is not a WebAuthn Assertion. It's enabled to seamlessly use both classic (password) and WebAuthn authentication procedures.

### 2. Publish files and migrate

With the single `webauthn:install` command, you can install the configuration, routes, and migration files.

```shell
php artisan webauthn:install
```

This will also publish a migration file needed to create a table to hold the WebAuthn Credentials (Passkeys). Once ready, migrate your application to create the table.

```shell
php artisan migrate
```

> [!TIP]
> 
> You can [modify the migration](DATABASE.md) if you need to, like changing the table name.

### 3. Implement the contract and trait

Add the `WebAuthnAuthenticatable` contract and the `WebAuthnAuthentication` trait to the User class, or any other that uses authentication.

```php
<?php

namespace App;

use Illuminate\Foundation\Auth\User as Authenticatable;
use Laragear\WebAuthn\Contracts\WebAuthnAuthenticatable;
use Laragear\WebAuthn\WebAuthnAuthentication;

class User extends Authenticatable implements WebAuthnAuthenticatable
{
    use WebAuthnAuthentication;

    // ...
}
```

From here you're ready to work with WebAuthn Authentication. The following steps will help you close the gap to a full implementation.

### 4. Register the routes and controllers

WebAuthn uses exclusive routes to register and authenticate users. Creating these routes and controller may be cumbersome, specially if it's your first time in the WebAuthn realm, so these are installed automatically at `Http\Controllers\WebAuthn` when using `webauthn:install`.

Go into your `web.php` routes file and register a default set of routes with the `\Laragear\WebAuthn\Http\Routes::register()` method. Since WebAuthn doesn't require protection for CSRF/XSRF tokens, you may disable it for these routes.

```php
// web.php
use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken;
use Illuminate\Support\Facades\Route;
use Laragear\WebAuthn\Http\Routes as WebAuthnRoutes;

Route::view('welcome');

// WebAuthn Routes
WebAuthnRoutes::register()->withoutMiddleware(VerifyCsrfToken::class);
```

> [!TIP]
> 
> The [`@laragear/webpass` javascript helper](#5-use-the-javascript-helper) supports adding CSRF/XSRF tokens manually.

The method allows to use different attestation and assertion paths, and even each of the controllers.

```php
use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken;
use Laragear\WebAuthn\Http\Routes as WebAuthnRoutes;

WebAuthnRoutes::register(
    attest: 'auth/register',
    assert: 'auth/login'
)->withoutMiddleware(VerifyCsrfToken::class);
```

> [!NOTE]
> 
> You can also delete the controllers and implement [attestation](#attestation) and [assertion](#assertion) manually.

### 5. Use the Javascript helper

This package original Javascript helper has been moved into its own package, called `@laragear/webpass`. You may use directly in your HTML application by just using JSDelivr CDN:

```html
<head>
    <script src="https://cdn.jsdelivr.net/npm/@laragear/webpass@2/dist/webpass.js" defer></script>
</head>

<body>
    <script async>
        if (Webpass.isUnsupported()) {
            alert("Your browser doesn't support WebAuthn.")
        }
        
        const { success } = await Webpass.attest("/webauthn/register/options", "/webauthn/register")
        
        if (success) {
            window.location.replace("/dashboard")
        }
    </script>
</body>
```

Alternatively, you may want to include it in your project dependencies if you're using a frontend framework like Vue, React, Angular or Svelte, to name a few.

```shell
npm i @laragear/webpass@2
```

Once done, you may attest and assert the authenticator using the `Webpass` object:

```javascript
import Webpass from "@laragear/webpass"

if (Webpass.isUnsupported()) {
    return alert("Your browser doesn't support WebAuthn.")
}

// Create new credentials for a logged in user
const { credential, success, error } = await Webpass.attest("/webauthn/register/options", "/webauthn/register")

// Check the credentials for a guest user
const { user, success, error } = await Webpass.assert("/webauthn/login/options", "/webauthn/login")
```

The Webpass helper offers more flexibility than just adjusting the WebAuthn ceremony paths. For more information, check [the documentation of `@laragear/webpass`](https://github.com/Laragear/webpass).

## Attestation

Attestation is the _ceremony_ to create WebAuthn Credentials. To create an Attestable Response that the user device can understand, use the `AttestationRequest::toCreate()` form request.

For example, we can create our own `WebAuthnRegisterController` to create it.

```php
// app\Http\Controllers\WebAuthn\WebAuthnRegisterController.php
use Laragear\WebAuthn\Http\Requests\AttestationRequest;

public function createChallenge(AttestationRequest $request)
{
    return $request->toCreate();
}
```

The device will receive the "instructions" to make a key, and will respond with it. You can use the `AttestedRequest` form request and its `save()` method to persist the WebAuthn key if it is valid. The request will automatically return a Validation exception if something fails.

```php
// app\Http\Controllers\WebAuthn\WebAuthnRegisterController.php
use Laragear\WebAuthn\Http\Requests\AttestedRequest;

public function register(AttestedRequest $attestation)
{
    $attestation->save();
    
    return 'Now you can login without passwords!';
}
```

You may pass an array, or a callback, to the `save()`, which will allow you to modify the underlying WebAuthn Eloquent Model before saving it. For example, we could add an alias for the key present in the Request data.

```php
// app\Http\Controllers\WebAuthn\WebAuthnRegisterController.php
use Laragear\WebAuthn\Http\Requests\AttestedRequest;

public function register(AttestedRequest $request)
{
    $request->validate(['alias' => 'nullable|string']);

    $attestation->save($request->only('alias'));
    
    // Same as:
    // $attestation->save(function ($credentials) use ($request) {
    //    $credentials->alias = $request->input('alias');
    // })
}
```

> [!IMPORTANT]
> 
> Both `AttestationRequest` and `AttestedRequest` require the authenticated user. If the user is not authenticated, an HTTP 403 status code will be returned. You may want to [temporarily log in](https://laravel.com/docs/authentication#authenticate-a-user-once) the user, or [attest manually](#manually-attesting-and-asserting).

### Attestation User verification

By default, the authenticator decides how to verify user when creating a credential. Some may ask to press a "Continue" button to confirm presence, others will verify the User with biometrics, patterns or passwords.

You can override this using `fastRegistration()` to only check for user presence if possible, or `secureRegistration()` to actively verify the User.

```php
// app\Http\Controllers\WebAuthn\WebAuthnRegisterController.php
use Laragear\WebAuthn\Http\Requests\AttestationRequest;

public function createChallenge(AttestationRequest $request)
{
    return $request->fastRegistration()->toCreate();
}
```

### Userless/One-touch/Typeless Login

When asking to create a credential, the server will tell the authenticator to _prefer_ resident keys, which saves the "Username ID" of the credential inside itself. This is what enables one click/tap login, without the need to specify the user credentials (like the email) beforehand.

If you want this to be mandatory, use the `userless()` method of the `AttestationRequest` form request.

```php
// app\Http\Controllers\WebAuthn\WebAuthnRegisterController.php
use Laragear\WebAuthn\Http\Requests\AttestationRequest;

public function registerDevice(AttestationRequest $request)
{
    return $request->userless()->toCreate();
}
```

Once the Resident Key is created, the authenticator will be able to find the correct credential for your web application by finding which credentials match your Relaying Party ID (like `my-app.com`), and show the user these credentials. This effectively eliminates the step of the user sending its username or email so the server can return which credentials ID the authenticator should use.

> [!IMPORTANT]
>
> The Authenticator WILL require [user verification](#attestation-user-verification) on login when using `userless()`. It's highly probable the user will also be asked for [user verification on login](#assertion-user-verification).

### Multiple credentials per device

By default, during Attestation, the device will be informed about the existing enabled credentials already registered in the application. This way the device can avoid creating another one for the same purpose.

You can enable multiple credentials per device using `allowDuplicates()`, which in turn will always return an empty list of credentials to exclude. This way the authenticator will _think_ there are no already stored credentials for your app, and create a new one.

```php
// app\Http\Controllers\WebAuthn\WebAuthnRegisterController.php
use Laragear\WebAuthn\Http\Requests\AttestationRequest;

public function registerDevice(AttestationRequest $request)
{
    return $request->allowDuplicates()->make();
}
```

### Custom name and display name

The application will use the user email as "name" and his name as "display name". Regardless of how authenticators will show it to the user, you may change these at runtime by using a callback. The callback will receive the user instance and a boolean if the attestation uses unique credentials, and should return an instance of `Laragear\WebAuthn\WebAuthnData`.

This may be convenient if you want to add a counter in case a user can register [more than one credential in one device](#multiple-credentials-per-device). 

```php
// app\Http\Controllers\WebAuthn\WebAuthnRegisterController.php
use App\Models\User;
use Illuminate\Support\Str;
use Laragear\WebAuthn\Http\Requests\AttestationRequest;
use Laragear\WebAuthn\WebAuthnData;

public function registerDevice(AttestationRequest $request)
{
    return $request->using(function (User $user, bool $usesUniqueCredentials) {
        // If it doesn't use unique credentials, add a counter for how many he has
        $counter = $usesUniqueCredentials
            ? ' #'. $user->webAuthnCredentials()->whereEnabled()->count() + 1
            : '';
            
        $displayName = $user->alias ?? $user->name ?? Str::before($user->email, '@');
    
        return WebAuthnData::make(
            name: $user->email,
            displayName: $displayName . $counter
        );
    })->make();
}
```

## Assertion

The Assertion procedure also follows a two-step procedure: the user will input its username, the server will return the IDs of the WebAuthn credentials to use, and the device pick one to sign the response. If you're using [userless login](#userlessone-touchtypeless-login), only the challenge is returned.

First, use the `AssertionRequest::toVerify()` form request. It will automatically create an assertion for the user that matches the credentials, or a blank one in case you're using [userless login](#userlessone-touchtypeless-login). Otherwise, you may set stricter validation rules to always ask for credentials.

For example, we can use our own `WebAuthnLoginController` to handle it.

```php
// app\Http\Controllers\WebAuthn\WebAuthnLoginController.php
use Laragear\WebAuthn\Http\Requests\AssertionRequest;

public function createChallenge(AssertionRequest $request)
{
    $request->validate(['email' => 'sometimes|email']);

    return $request->toVerify($request->only('email'));
}
```

After that, you may receive the challenge using the `AssertedRequest` request object by just type-hinting it in the controller.

Since the authentication is pretty much straightforward, you only need to check if the `login()` method returns the newly authenticated user or `null` when it fails. When it's a success, it will take care of [regenerating the session](https://laravel.com/docs/11.x/session#regenerating-the-session-id) for you.

```php
// app\Http\Controllers\WebAuthn\WebAuthnLoginController.php
use Laragear\WebAuthn\Http\Requests\AssertedRequest;

public function createChallenge(AssertedRequest $request)
{
    $user = $request->login();
    
    return $user 
        ? response("Welcome back, $user->name!");
        : response('Something went wrong, try again!');
}
```

You can also use the `login()` method will callbacks, which will be passed to the [`attemptWhen()`](https://laravel.com/docs/11.x/authentication#specifying-additional-conditions) method of the Session Guard.

```php
// app\Http\Controllers\WebAuthn\WebAuthnLoginController.php
use Laragear\WebAuthn\Http\Requests\AssertedRequest;

public function createChallenge(AssertedRequest $request)
{
    $user = $request->login(callbacks: fn ($user) => $user->isNotBanned());
    
    return $user 
        ? response("Welcome back, $user->name!");
        : response('Something went wrong, try again!');
}
```

If you need greater control on the Assertion procedure, you may want to [Assert manually](#manually-attesting-and-asserting).

### Assertion User Verification

In the same style of [attestation user verification](#attestation-user-verification), the authenticator decides if it should verify the user on login or not. 

You may only require the user presence with `fastLogin()`, or actively verify the user with `secureLogin()`.

```php
// app\Http\Controllers\WebAuthn\WebAuthnLoginController.php
use Laragear\WebAuthn\Http\Requests\AssertionRequest;

public function createChallenge(AssertionRequest $request)
{
    $request->validate(['email' => 'sometimes|email']);

    return $request->fastLogin()->toVerify($request->only('email'));
}
```

### Password Fallback

By default, the `eloquent-webauthn` can be used to log in users with passwords when the credentials are not a WebAuthn JSON payload, like a password. This way, your normal Authentication flow is unaffected:

```php
// app\Http\Controllers\Auth\LoginController.php
use Illuminate\Support\Facades\Auth;

public function login(Request $request)
{
    $request->validate(['email' => 'required|email', 'password' => 'required|string']);

    if (Auth::attempt($request->only('email', 'password'))) {
        return redirect()->home();
    }
    
    return back()->withErrors(['email' => 'No user found with these credentials']);
}
```

You may disable the fallback to only allow WebAuthn authentication by [setting `password_fallback` to `false`](#1-add-the-webauthn-driver). This may force you to handle classic user/password using a separate guard.

### Detecting Cloned Credentials

During assertion, the package will automatically detect if a Credential has been cloned by comparing how many times the user has logged in with it.

When it's detected as cloned, the Credential will be immediately disabled and the Assertion will be denied.

Additionally, the [`CredentialCloned`](#events) event will be fired, which you can use to warn the user.

```php
use Illuminate\Support\Facades\Event;
use Laragear\WebAuthn\Events\CredentialCloned;
use App\Notifications\SecureYourDevice;

Event::listen(CredentialCloned::class, function ($cloned) {
    $notification = new SecureYourDevice($cloned->credential);
    
    $cloned->credential->user->notify($notification);
});
```

## Managing Credentials

The purpose of the `WebAuthnAuthenticatable` contract is to allow managing credentials within the User instance. The most useful methods are:

* `webAuthnData()`: Returns the non-variable WebAuthn user data to create credentials.
* `flushCredentials()`: Removes all credentials. You can exclude credentials by their id.
* `disableAllCredentials()`: Disables all credentials. You can exclude credentials by their id.
* `makeWebAuthnCredential()`: Creates a new WebAuthn Credential instance.
* `webAuthnCredentials()`: [One-to-Many](https://laravel.com/docs/11.x/eloquent-relationships#one-to-many-polymorphic-relations) relation to query for WebAuthn Credentials.

You can use these methods to, for example, find a credential to blacklist, or disable WebAuthn completely by flushing all registered devices.

## Events

The following events are fired by this package, which you can [listen to in your application](https://laravel.com/docs/11.x/events):

| Event                | Description                                                           |
|----------------------|-----------------------------------------------------------------------|
| `CredentialCreated`  | An User has registered a new WebAuthn Credential through Attestation. |
| `CredentialEnabled`  | A disabled WebAuthn Credential was enabled using `enable()`.          |
| `CredentialDisabled` | A enabled WebAuthn Credential was disabled using `disable()`.         |
| `CredentialCloned`   | A WebAuthn Credential was detected as cloned dring Assertion.         |
| `CredentialAttested` | A WebAuthn Credential was used to successfully complete Attestation.  |
| `CredentialAsserted` | A WebAuthn Credential was used to successfully complete Assertion.    |

## Manually Attesting and Asserting

If you want to manually Attest and Assert users, for example to create users at the same time they register (attest) a device, you may instance their respective pipelines used for both WebAuthn Ceremonies:

| Pipeline               | Description                                          |
|------------------------|------------------------------------------------------|
| `AttestationCreator`   | Creates a request to create a WebAuthn Credential.   |
| `AttestationValidator` | Validates a response with the WebAuthn Credential.   |
| `AssertionCreator`     | Creates a request to validate a WebAuthn Credential. |
| `AssertionValidator`   | Validates a response for a WebAuthn Credential.      |

> [!IMPORTANT]
> 
> The `AttestationValidator` instances a storable credential, it doesn't save it. This way you have the chance to alter the model with additional data before persisting.

Compared to prior versions, the validation data to pass through `AttestationValidator` and `AssertionValidator` no longer require the current Request instance. Instead, these only need the JSON array of data. 

If you prefer, you can still use the `fromRequest()` helper, which will extract the required WebAuthn data from the current or issued Request instance, or manually instance a `Laragear\WebAuthn\JsonTransport` with the required data.

```php
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;

$assertion = AssertionValidation::fromRequest();

// Same as...
$assertion = new AssertionValidation(
    new JsonTransport($request->json(AssertionValidation::REQUEST_KEYS))
);
```

Going back to the pipeline usage, let's imagine you want to manually authenticate a user with its WebAuthn Credentials. For that, you can type-hint the `AssertionValidator` pipeline in a Controller action argument and Laravel will automatically inject the instance to it.

```php
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidator;
use Illuminate\Support\Facades\Auth;

public function authenticate(Request $request, AssertionValidator $assertion)
{
    $credential = $assertion
        ->send(AssertionValidation::fromRequest($request))
        ->thenReturn()
        ->credential;
    
    Auth::login($credential->user);
    
    return "Welcome aboard, {$credential->user->name}!";
}
```

Since these are Laravel Pipelines, you're free to push additional pipes. These pipes can be a class with `handle()`, or just a function that receives the validation procedure.

```php
use Laragear\WebAuthn\Assertion\Validator\AssertionValidator;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Exception;

public function authenticate(Request $request, AssertionValidator $assertion)
{
    $credential = $assertion
        ->send(AssertionValidation::fromRequest($request))
        // Add new pipes to the validation.
        ->pipe(function($validation, $next) {
            if ($validation->user?->isNotAwesome()) {
                throw new Exception('The user is not awesome');
            }

            return $next($validation);
        })
        ->thenReturn()
        ->credential;
    
    Auth::login($credential->user);
    
    return "Welcome aboard, {$credential->user->name}!";
}
```

Alternatively, you may add new pipes globally in the `registered()` method of your `bootstrap/app.php` file, just by [extending the binding](https://laravel.com/docs/11.x/container#extending-bindings).

```php
use Laragear\WebAuthn\Assertion\Validator\AssertionValidator;
use Illuminate\Foundation\Application;

return Application::configure(basePath: dirname(__DIR__))
    ->registered(function (Application $app) {
        $app->extend(AssertionValidator::class, function ($pipeline) {
            return $pipeline->pipe([
                \App\Auth\WebAuthn\CheckIfUserIsCool::class,
                \App\Auth\WebAuthn\LoginUser::class,
                \App\Auth\WebAuthn\SendLoginNotification::class,
            ]);
        })
    })
    ->create();
```

> [!WARNING]
>
> The pipes list and the pipes themselves are **not covered by API changes**, and are marked as `internal`. These may change between minor or patch versions without notice. 

## [Migrations](DATABASE.md)

## Challenges

Challenges are primordial to each WebAuthn ceremony. It's the only way to check if both the authenticator and application (Relying Party) have the same cryptographical key pair.

While this library works using known secure defaults, you can change how challenges are created, and how these are managed from a given store.

### Custom Challenges

Challenges are created automatically using the library configuration. Most of the time, you won't need to change how a Challenge is created.

There may be some scenarios where you will want to create a custom challenge. For example, you need to base it on predefined piece of data, or especial properties for specific devices. You may add your own Challenge, with the Byte Buffer required to be transmitted, to the data being passed to the [`AttestationCreator` and `AssertionCreator` pipelines](#manually-attesting-and-asserting).

```php
use FIDO\Generator;
use Laragear\WebAuthn\Attestation\Creator\AttestationCreation;
use Laragear\WebAuthn\Attestation\Creator\AttestationCreator;
use Laragear\WebAuthn\Challenge\Challenge;

public function create(Request $request, AttestationCreator $assertion)
{
    $byteBuffer = Generator::lowPowerRandom();
    
    $creation = new AttestationCreation(
        user: $request->user(),
        challenge: Challenge::make($byteBuffer, 60) 
    );

    return $assertion
        ->send($creation)
        ->thenReturn()
        ->json;
}
```

### Custom Challenge Repository

Storing and pulling challenges is done through a _repository_. By default, this library includes a repository that uses your application Session, which is the easiest and securer way to store and pull challenges.

You may want to use your own, for example, if you need to _share_ the challenges across multiple application instances, or a common database table. Whatever is your use case, start by creating a class implementing the `Laragear\WebAuthn\Contracts\WebAuthnChallengeRepository` contract.

The class should be able to store a `Challenge` instance, and pull it if it exists. Note that when it's pulled, the data is deleted from the repository.

```php
namespace App\WebAuthn;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Request;
use Laragear\WebAuthn\Assertion\Creator\AssertionCreation;
use Laragear\WebAuthn\Assertion\Validator\AssertionValidation;
use Laragear\WebAuthn\Attestation\Creator\AttestationCreation;
use Laragear\WebAuthn\Attestation\Validator\AttestationValidation;
use Laragear\WebAuthn\Contracts\WebAuthnChallengeRepository;
use Laragear\WebAuthn\Challenge\Challenge;

class MyRepository implements WebAuthnChallengeRepository
{
    /**
     * Puts a ceremony challenge into the repository.
     */
    public function store(Challenge $challenge, AttestationCreation|AssertionCreation $ceremony): void
    {  
        Cache::store('redis')->put($this->getFingerprint(), $challenge, $challenge->expiresAt())
    }

    /**
     * Pulls a ceremony challenge out from the repository, if it exists.
     */
    public function pull(AttestationValidation|AssertionValidation $ceremony): ?Challenge
    {      
        return Cache::store('redis')->pull($this->getFingerprint());
    }
    
    /**
     * Create a fingerprint as a cache key.
     */
    protected function getFingerprint(): string
    {
        $user = Auth::user();
        
        // Use the IP, the user class and its auth identifier to build the cache key.
        // This should ensure the challenge is unique for the IP and the user.
        return implode('|', [
            'webauthn_challenge', Request::ip(), get_class($user), $user->getAuthIdentifier()
        ]);
    }
}
```

After that, _replace_ the default challenge repository resolver in the application container, ideally in your `registered()` method of your `bootstrap/app.php` file.

```php
use App\WebAuthn\MyRepository;
use Illuminate\Foundation\Application;
use Laragear\WebAuthn\Contracts\WebAuthnChallengeRepository;

return Application::configure(basePath: dirname(__DIR__))
    ->registered(function ($app) {
        $app->singleton(WebAuthnChallengeRepository::class, fn () => new MyRepository())
    })
    ->create();
    
```

## Origins

If you have an [Android app](https://developer.android.com/identity/sign-in/credential-manager?hl=en#verify-origin), or any other remote frontends, software or interfaces outside your app server to handle credentials on behalf of your app, you may need to add these as valid origins. These are additional to your main Relying Party ID, which is your app domain.

Simply add these origins as part of the `WEBAUTHN_ORIGINS` environment variable. If you have more than one, you can separate them using a comma.

```dotenv
WEBAUTHN_ORIGINS=mirror-myapp.com,android:apk-key-hash:kffL-daBUxvHpY-4M8yhTavt5QnFEI2LsexohxrGPYU
```

## Advanced Configuration

Laragear WebAuthn was made to work out-of-the-box, but you can override the configuration by simply publishing the config file.

```shell
php artisan vendor:publish --provider="Laragear\WebAuthn\WebAuthnServiceProvider" --tag="config"
```

After that, you will receive the `config/webauthn.php` config file with an array like this:

```php
<?php

return [
    'relying_party' => [
        'name' => env('WEBAUTHN_NAME', env('APP_NAME')),
        'id'   => env('WEBAUTHN_ID'),
    ],
    'origins' => env('WEBAUTHN_ORIGINS'),
    'challenge' => [
        'bytes' => 16,
        'timeout' => 60,
        'key' => '_webauthn',
    ]
];
```

### Relying Party Information

```php
return [
    'relying_party' => [
        'name' => env('WEBAUTHN_NAME', env('APP_NAME')),
        'id'   => env('WEBAUTHN_ID'),
    ],
];
```

The _Relying Party_ is just a way to uniquely identify your application in the user device:

* `name`: The name of the application. Defaults to the application name.
* `id`: An unique ID the application, [recommended to be the site domain](https://www.w3.org/TR/webauthn-2/#rp-id). If `null`, the device _may_ fill it internally, usually as the full domain.

> [!WARNING]
>
> WebAuthn authentication only work on the top domain it was registered. 

Instead of modifying the config file, you should use the environment variables to set the name and ID for WebAuthn.

```dotenv
WEBAUTHN_NAME=SecureBank
WEBAUTHN_ID=auth.securebank.com
```

### Origins

```php
return [
    'origins' => env('WEBAUTHN_ORIGINS'),
];
```

This holds the [additional origins](#origins) your application may accept for attestation and assertion. You should use the `WEBAUTHN_ORIGINS` environment variable to change this value. 

### Challenge configuration

```php
return [
    'challenge' => [
        'bytes' => 16,
        'timeout' => 60,
        'key' => '_webauthn',
    ]
];
```

The outgoing challenges are random string of bytes. This controls how many bytes, the seconds which the challenge is valid, and the session key used to store the challenge while its being resolved by the device.

## Laravel UI, Jetstream, Fortify, Sanctum, Breeze, Inertia and Livewire

In _theory_ this package should work without any problems with these packages, but you may need to override or _redirect_ the authentication flow (read: override methods) to one using WebAuthn.

There is no support for using WebAuthn with these packages because these are meant to be used with classic user-password authentication. Any issue regarding these packages will be shot down with extreme prejudice.

If you think WebAuthn is critical for these packages, [consider supporting this package](#keep-this-package-free).

## FAQ

* **Does this work with any browser?**

[Yes](https://caniuse.com/#feat=webauthn). In the case of ancient browsers, you should have a fallback detection script. This can be asked with [the included JavaScript helper](#5-use-the-javascript-helper) in a breeze:

```javascript
if (WebAuthn.isNotSupported()) {
   alert('Your device is not secure enough to use this site!');
}
```

* **Does this store the user fingerprints, PINs or patterns in my site?**

No.

WebAuthn stores a private key on the user device, and transmit a public key to the application. These do not have any correlation to the user biometric data or passwords.

* **Can a phishing site steal WebAuthn credentials and use them in my site to impersonate a user?**

No, WebAuthn _kills the phishing_.

Unlike passwords, the private key never leaves the device, and the key-pair is bound to the top-most domain it was registered.

A user being _phished_ at `staetbank.com` won't be able to log in with a key made on the legit site `statebank.com`, as the device won't be able to find it.

* **Can WebAuthn data identify a particular device?**

No, unless explicitly [requested](https://www.w3.org/TR/webauthn-2/#attestation-conveyance) and consented.

This package doesn't support other attestation conveyances than `none`, so that data is not received by the app.

* **Are my user's classic passwords safe?**

Yes, as long you are hashing them as you should. This is done by Laravel by default. 

You can also [disable them](#password-fallback) and make your site only compatible with WebAuthn.

* **Can a user register two or more different _devices_ for the same account?**

Yes. A User can register his PC and his Phone separately.

Some devices _may_ sync their _passkeys_ between his devices, like Safari on iPhone, iPad and macOS. That type of sync is up to the manufacturer and OS.

* **Can a user register two or more _credentials_ in the same device?**

Not by default, but [you can enable it](#multiple-credentials-per-device).

* **If a user loses his device, can he register a new device?**

Yes.

If you're not using a [password fallback](#password-fallback), you may need to create a logic to register a new device using an email or SMS. It's assumed he is reading his email using a trusted device.

* **What's the difference between disabling and deleting a credential?**

Disabling a credential doesn't delete it, so it's useful as a blacklisting mechanism and these can also be re-enabled later.

When the credential is deleted, it goes away forever from the server, so the credential in the authenticator device becomes orphaned.

* **Can I delete a credential from the user device?**

No, there is no protocol in WebAuthn to delete a credential from the device or authenticator.

That process must be done manually by the user in his device, and will vary depending on the browser, OS and device hardware.

* **How secure is this against passwords or 2FA?**

Extremely secure since it works only on HTTPS (or `localhost`). Also, no password or codes are exchanged nor visible in the screen.

* **Can I deactivate the password fallback? Can I enforce only WebAuthn authentication and nothing else?**

[Yes](#password-fallback). Just be sure to create recovery helpers to avoid locking out your users.

* **Does this include JavaScript to handle WebAuthn in the frontend?**

It's encouraged to [use Webpass package](#5-use-the-javascript-helper).

Alternatively, for complex WebAuthn management, consider using the [`navigator.credentials`](https://developer.mozilla.org/en-US/docs/Web/API/Navigator/credentials) API directly.

* **The attestation is fine, but assertion never logs in the user**

This happens because you forgot [the first step](#1-add-the-webauthn-driver), using the WebAuthn driver to authenticate users.

If you believe it's a deep problem, try to use [`navigator.credentials`](https://developer.mozilla.org/en-US/docs/Web/API/Navigator/credentials) directly to find if the problem lies on the library or the frontend.

* **Does WebAuthn eliminate bots? Can I forget about _captchas_?**

Yes and no. To register users, you still need to use [captcha](https://github.com/Laragear/ReCaptcha), honeypots, or other mechanisms to stop bots from filling forms.

Once a user is registered, bots won't be able to log in because the real user is the only one that has the private key required for WebAuthn.

* **Does this encode/decode the WebAuthn data automatically in the frontend?**

Yes, the [Webpass helper](#5-use-the-javascript-helper) does it automatically for you.

* **Does this encrypt the public keys?**

Yes, public keys are encrypted when saved into the database with your app key.

* **I changed my `APP_KEY` and nobody can log in**

Laravel, since version 11.x, includes a [key rotation mechanism](https://laravel.com/docs/11.x/encryption#gracefully-rotating-encryption-keys) to avoid locking out all your users if you change your `APP_KEY`.

Older Laravel versions will require re-encryption. You will have to manually create a console command that decrypts (with the old key) and re-encrypts (with the new key) the `public_key` column of the table where the authentication data is.

* **Does this include WebAuthn credential recovery routes?**

No. You're free to create your own flow for recovery.

My recommendation is to email the user, pointing to a signed route that registers a new device, and immediately redirect him to blacklist which credential was lost (or blacklist the only one he has).

* **Can I use my smartphone as authenticator through my PC or Mac?**

Sometimes.

While this is entirely up to hardware, OS and browser vendor themselves, modern _platforms_ will show a QR code, push notification, or connect to your smartphone via Bluetooth or NFC to complete the WebAuthn ceremony. Please check your target platforms of choice.

* **Why my device doesn't show Windows Hello/Passkey/TouchID/FaceID/OpticID/pattern/fingerprint authentication?**

By default, this WebAuthn works on _almost_ everything. Some combinations of devices, OS and Web browsers may differ on what to make available for WebAuthn authentication. 

You may [check this site for authenticator support](https://webauthn.me/browser-support).

* **Why my device doesn't work at all with this package?**

This package supports WebAuthn 2.0, which is [W3C Recommendation](https://www.w3.org/TR/webauthn-2). Your device/OS/browser may be using an unsupported version.

There are no plans to support older WebAuthn specs. The new [WebAuthn 3.0 draft](https://www.w3.org/TR/webauthn-3) spec needs to be finished to be supported.

* **I'm trying to test this in my development server, but it doesn't work**

Use `localhost` exclusively (not `127.0.0.1` or `::1`) or use a proxy to tunnel your site through HTTPS. WebAuthn only works on `localhost` or under `HTTPS` only.

* **Why this package supports only `none` attestation conveyance?**

Because `direct`, `indirect` and `enterprise` attestations are mostly used on high-security high-risk scenarios, where an entity has total control on the devices used to authenticate. Imagine government, finance, medical, or military.

If you deem this feature critical for you, [**consider supporting this package**](#become-a-sponsor).

* **Can I allow logins with only USB keys?**

No. Is encouraged to use whatever to authenticate in your app.

* **Everytime I make attestations or assertions, it says no challenge exists!** 

Remember that your WebAuthn routes **must use Sessions**, because the Challenges are stored there by default.

Session are automatically started on the `web` route group, or using the `StartSession` middleware directly. You can check this on your [HTTP Kernel Middleware](https://laravel.com/docs/11.x/middleware#middleware-groups).

* **My ceremonies always fail. How I can debug this package?**

If you have [debugging enabled](https://laravel.com/docs/11.x/configuration#debug-mode), like on development environments, the assertion data is logged in your [application logs](https://laravel.com/docs/11.x/logging).

The rest of errors are thrown as-is. You may want to log them manually using [Laravel's Error Handler](https://laravel.com/docs/11.x/errors) depending on the case. 

* **Can I publish only some files?**

Yes. Instead of using `webauthn:install`, use `vendor:publish` and follow the prompts.

* **Why `ext-sodium` is required as optional?**

Some authenticators can create EdDSA 25519 public keys, which are part of [W3C WebAuthn 3.0 draft](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-pubkeycredparams). These keys are shorter and don't require too much computational power to verify, which opens the usage for low-power or "passive" authenticators (like NFC smart-cards). 

If `sodium` or the [`paragonie/sodium-compat`](https://github.com/paragonie/sodium_compat) package is not installed, the server won't report EdDSA 25519 compatibility to the authenticator, and any EdDSA 25519 public key previously stored will fail validation. 

Consider also that there are no signs of EdDSA 25519 incorporation into PHP `ext-openssl` extension, as this algorithm is exclusive to the `sodium` extension.

## Laravel Octane Compatibility

* There are no singletons using a stale application instance.
* There are no singletons using a stale config instance.
* There are no singletons using a stale request instance.
* There are no static properties written during a request.

There should be no problems using this package with Laravel Octane.

## Security

These are some details about this WebAuthn implementation you should be aware of.

* Registration (attestation) and Login (assertion) challenges use the request session by default.
* Only one ceremony can be done at a time, because ceremonies use the same challenge key. 
* Challenges are created with random bytes and checked on ceremony validation.
* Challenges are pulled (retrieved and deleted from source) on resolution.
* All challenges and ceremonies expire after 60 seconds.
* WebAuthn User Handle is UUID v4.
* User Handle is reused when a new credential for the same user is created.
* Credentials can be blacklisted (enabled/disabled).
* Public Keys are encrypted in the database automatically, using the application key.

If you discover any security related issues, please email darkghosthunter@gmail.com instead of using the issue tracker.

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.

Contains Code from [Lukas Buchs WebAuthn 2.0](https://github.com/lbuchs/WebAuthn) implementation. The MIT License (MIT) where applicable.

Laravel is a Trademark of Taylor Otwell. Copyright © 2011-2025 Laravel LLC.
