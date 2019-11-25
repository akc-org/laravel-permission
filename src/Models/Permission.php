<?php

namespace Spatie\Permission\Models;

use Spatie\Permission\Guard;
use Illuminate\Support\Collection;
use Spatie\Permission\Traits\HasRoles;
use Illuminate\Database\Eloquent\Model;
use Spatie\Permission\PermissionRegistrar;
use Spatie\Permission\Traits\RefreshesPermissionCache;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Spatie\Permission\Exceptions\PermissionDoesNotExist;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Spatie\Permission\Exceptions\PermissionAlreadyExists;
use Spatie\Permission\Contracts\Permission as PermissionContract;

class Permission extends Model implements PermissionContract
{
    use HasRoles;
    use RefreshesPermissionCache;

    protected $guarded = ['id'];

    private $nameAttribute;

    private $guardNameAttribute;

    public function __construct(array $attributes = [])
    {
        $this->timestamps = config('permission.models.timestamps');
        $this->nameAttribute = config('permission.column_names.permissions_name_key');
        $this->guardNameAttribute = config('permission.column_names.permissions_guard_name_key');

        $attributes[$this->guardNameAttribute] = $attributes[$this->guardNameAttribute] ?? config('auth.defaults.guard');

        parent::__construct($attributes);

        $this->setTable(config('permission.table_names.permissions'));
    }

    public static function create(array $attributes = [])
    {
        $nameAttribute = config('permission.column_names.permissions_name_key');
        $guardNameAttribute = config('permission.column_names.permissions_guard_name_key');

        $attributes[$guardNameAttribute] = $attributes[$guardNameAttribute] ?? Guard::getDefaultName(static::class);

        $permission = static::getPermissions([
            $nameAttribute => $attributes[$nameAttribute],
            $guardNameAttribute => $attributes[$guardNameAttribute]
        ])->first();

        if ($permission) {
            throw PermissionAlreadyExists::create($attributes[$nameAttribute], $attributes[$guardNameAttribute]);
        }

        return static::query()->create($attributes);
    }

    /**
     * A permission can be applied to roles.
     */
    public function roles(): BelongsToMany
    {
        return $this->belongsToMany(
            config('permission.models.role'),
            config('permission.table_names.role_has_permissions'),
            config('permission.column_names.role_has_permissions_permission_id_key'),
            config('permission.column_names.role_has_permissions_role_id_key')
        );
    }

    /**
     * A permission belongs to some users of the model associated with its guard.
     */
    public function users(): MorphToMany
    {
        return $this->morphedByMany(
            getModelForGuard($this->getGuardNameAttribute()),
            config('permission.column_names.model_has_permissions_relation_name'),
            config('permission.table_names.model_has_permissions'),
            config('permission.column_names.model_has_permissions_permission_id_key'),
            config('permission.column_names.model_morph_key')
        );
    }

    /**
     * Find a permission by its name (and optionally guardName).
     *
     * @param string $name
     * @param string|null $guardName
     *
     * @throws \Spatie\Permission\Exceptions\PermissionDoesNotExist
     *
     * @return \Spatie\Permission\Contracts\Permission
     */
    public static function findByName(string $name, $guardName = null): PermissionContract
    {
        $nameAttribute = config('permission.column_names.permissions_name_key');
        $guardNameAttribute = config('permission.column_names.permissions_guard_name_key');

        $guardName = $guardName ?? Guard::getDefaultName(static::class);

        $permission = static::getPermissions([$nameAttribute => $name, $guardNameAttribute => $guardName])->first();
        if (! $permission) {
            throw PermissionDoesNotExist::create($name, $guardName);
        }

        return $permission;
    }

    /**
     * Find a permission by its id (and optionally guardName).
     *
     * @param int $id
     * @param string|null $guardName
     *
     * @throws \Spatie\Permission\Exceptions\PermissionDoesNotExist
     *
     * @return \Spatie\Permission\Contracts\Permission
     */
    public static function findById(int $id, $guardName = null): PermissionContract
    {
        $guardNameAttribute = config('permission.column_names.permissions_guard_name_key');

        $guardName = $guardName ?? Guard::getDefaultName(static::class);

        $permission = static::getPermissions(['id' => $id, $guardNameAttribute => $guardName])->first();

        if (! $permission) {
            throw PermissionDoesNotExist::withId($id, $guardName);
        }

        return $permission;
    }

    /**
     * Find or create permission by its name (and optionally guardName).
     *
     * @param string $name
     * @param string|null $guardName
     *
     * @return \Spatie\Permission\Contracts\Permission
     */
    public static function findOrCreate(string $name, $guardName = null): PermissionContract
    {
        $nameAttribute = config('permission.column_names.permissions_name_key');
        $guardNameAttribute = config('permission.column_names.permissions_guard_name_key');

        $guardName = $guardName ?? Guard::getDefaultName(static::class);

        $permission = static::getPermissions([$nameAttribute => $name, $guardNameAttribute => $guardName])->first();

        if (! $permission) {
            return static::query()->create([$nameAttribute => $name, $guardNameAttribute => $guardName]);
        }

        return $permission;
    }

    /**
     * Get the current cached permissions.
     */
    protected static function getPermissions(array $params = []): Collection
    {
        return app(PermissionRegistrar::class)
            ->setPermissionClass(static::class)
            ->getPermissions($params);
    }

    /**
     * Name attribute getter.
     *
     * @return string
     */
    public function getNameAttribute(): string
    {
        return $this->attributes[$this->nameAttribute];
    }

    /**
     * Name attribute setter.
     *
     * @param $value string
     */
    public function setNameAttribute($value): void
    {
        $this->attributes[$this->nameAttribute] = $value;
    }

    /**
     * Guard name attribute getter.
     *
     * @return string
     */
    public function getGuardNameAttribute(): string
    {
        return $this->attributes[$this->guardNameAttribute];
    }

    /**
     * Guard name attribute setter.
     *
     * @param $value string
     */
    public function setGuardNameAttribute($value): void
    {
        $this->attributes[$this->guardNameAttribute] = $value;
    }
}
