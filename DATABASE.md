# Model customization

You can further customize the package Models using the `customize()` method with a callback that receives the freshly instanced model instance. For example, you may want to hide some attributes, or change the table and connection the Model by default. Preferably, you would do this in your `bootstrap/app.php`.

```php
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Vendor\Package\Models\Driver;

return Application::configure(basePath: dirname(__DIR__))
    ->booted(function () {
        // Customize the model
        Car::customize(function (Car $model) {
            $model->setTable('my_custom_car');
            $model->setConnection('readonly-mysql');
            
            $model->setHidden('private_notes');
        })
    })->create();
```

> [!TIP]
>
> For your convenience, the Migration will automatically pick up the table and connection you set in the Model.

# Migration customization

The library you have installed comes with a very hands-off approach for migrations. If you check the new migrations published at `database/migrations`, you will find something very similar to this:

```php
// database/migrations/2022_01_01_193000_create_cars_migration.php
use Vendor\Package\Models\Car;

return Car::migration();
```

Worry not, the migration will still work. It has been _simplified_ for easy customization.

## Adding columns

To add columns to the migration, add a callback to the `with()` method. The callback will receive the table blueprint so you can modify the table while it's being created.

```php
use Illuminate\Database\Schema\Blueprint;
use Laragear\Package\Models\Car;

return Car::migration()->with(function (Blueprint $table) {
    $table->boolean('is_cool')->default(true);
    $table->string('color');
});
```

> [!NOTE]
> 
> The columns you add will be created _after_ the package adds its own columns. In other words, these will be set at the end of the table. 

### Relationships

If the package supports it, you may add relationships through their proper migration columns. For example, if we want to add the `driver` relationship to the model, we can use the native `resolveRelationUsing()` on your `bootstrap/app.php()`.

```php
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Vendor\Package\Models\Driver;

return Application::configure(basePath: dirname(__DIR__))
    ->booted(function () {
        // Add the relationship.
        Car::resolveRelationUsing('driver', function (Car $car) {
            return $car->belongsTo(Driver::class, 'driver_id')
        })
    })->create();
```

In the published package migration, you should be able to add the required column to connect your model like normal. In this case, we can use the [`foreignIdFor()`](https://laravel.com/docs/migrations#column-method-foreignIdFor) method to safely set the proper column type.

```php
use App\Models\Driver;
use Illuminate\Database\Schema\Blueprint;
use Laragear\Package\Models\Car;

return Car::migration(function (Blueprint $table) {
    // ...
    
    $table->foreignIdFor(Driver::class);
});
```

## After Up & Before Down

If you need to execute logic after creating the table, or before dropping it, use the `afterUp()` and `beforeDown()` methods, respectively.

```php
use Illuminate\Database\Schema\Blueprint;
use Laragear\Package\Models\Car;

return Car::migration()
    ->afterUp(function (Blueprint $table) {
        $table->foreignId('sociable_id')->references('id')->on('users');
    })
    ->beforeDown(function (Blueprint $table) {
        $table->dropForeign('sociable_id');
    });
```

## Morphs

This package _may_ create a morph relation automatically, with the intent to easily handle default relationship across multiple models. For example, a morph migration to support an `owner` being either one of your models `Company` or `Person`.

```php
use Laragear\Package\Models\Car;

$car = Car::find(1);

$owners = $car->owner; // App/Models/Company or App/Models/Person
```

You may find yourself with models a given primary key type, but the package migration using morphs for the other type. For example, your `Company` or `Person` models using UUID, while the migration morph type uses integers.

If that's your case, you can change the morph type with the `morph...` property access (preferably), or the `morph()` method with `numeric`, `uuid` or `ulid` if you need to also set an index name (in case your database engine doesn't play nice with large ones).

For example, you can change the morph type of the `Car` migration to match the UUID type for the `Company` and `Person` models.

```php
use Illuminate\Database\Schema\Blueprint;
use Laragear\Package\Models\Car;

return Car::migration()->morphUuid;

return Car::migration()->morph('uuid', 'shorter_morph_index_name');
```
