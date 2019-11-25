<?php

namespace Spatie\Permission\Models;

use Spatie\Permission\Guard;
use Illuminate\Database\Eloquent\Model;
use Spatie\Permission\Traits\HasPermissions;
use Spatie\Permission\Exceptions\RoleDoesNotExist;
use Spatie\Permission\Exceptions\GuardDoesNotMatch;
use Spatie\Permission\Exceptions\RoleAlreadyExists;
use Spatie\Permission\Contracts\Role as RoleContract;
use Spatie\Permission\Traits\RefreshesPermissionCache;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

class Role extends Model implements RoleContract
{
    use HasPermissions;
    use RefreshesPermissionCache;

    protected $guarded = ['id'];

    private $nameAttribute;

    private $guardNameAttribute;

    public function __construct(array $attributes = [])
    {
        $this->timestamps = config('permission.models.timestamps');
        $this->nameAttribute = config('permission.column_names.roles_name_key');
        $this->guardNameAttribute = config('permission.column_names.roles_guard_name_key');

        $attributes[$this->guardNameAttribute] = $attributes[$this->guardNameAttribute] ?? config('auth.defaults.guard');

        parent::__construct($attributes);

        $this->setTable(config('permission.table_names.roles'));
    }

    public static function create(array $attributes = [])
    {
        $nameAttribute = config('permission.column_names.roles_name_key');
        $guardNameAttribute = config('permission.column_names.roles_guard_name_key');

        $attributes[$guardNameAttribute] = $attributes[$guardNameAttribute] ?? Guard::getDefaultName(static::class);

        if (
            static::where($nameAttribute, $attributes[$nameAttribute])
            ->where($guardNameAttribute, $attributes[$guardNameAttribute]
            )->first()
        ) {
            throw RoleAlreadyExists::create($attributes[$nameAttribute], $attributes[$guardNameAttribute]);
        }

        return static::query()->create($attributes);
    }

    /**
     * A role may be given various permissions.
     */
    public function permissions(): BelongsToMany
    {
        return $this->belongsToMany(
            config('permission.models.permission'),
            config('permission.table_names.role_has_permissions'),
            config('permission.column_names.role_has_permissions_role_id_key'),
            config('permission.column_names.role_has_permissions_permission_id_key')
        );
    }

    /**
     * A role belongs to some users of the model associated with its guard.
     */
    public function users(): MorphToMany
    {
        return $this->morphedByMany(
            getModelForGuard($this->getGuardNameAttribute()),
            config('permission.column_names.model_has_roles_relation_name'),
            config('permission.table_names.model_has_roles'),
            config('permission.column_names.model_has_roles_role_id_key'),
            config('permission.column_names.model_morph_key')
        );
    }

    /**
     * Find a role by its name and guard name.
     *
     * @param string $name
     * @param string|null $guardName
     *
     * @return \Spatie\Permission\Contracts\Role|\Spatie\Permission\Models\Role
     *
     * @throws \Spatie\Permission\Exceptions\RoleDoesNotExist
     */
    public static function findByName(string $name, $guardName = null): RoleContract
    {
        $nameAttribute = config('permission.column_names.roles_name_key');
        $guardNameAttribute = config('permission.column_names.roles_guard_name_key');

        $guardName = $guardName ?? Guard::getDefaultName(static::class);

        $role = static::where($nameAttribute, $name)->where($guardNameAttribute, $guardName)->first();

        if (! $role) {
            throw RoleDoesNotExist::named($name);
        }

        return $role;
    }

    public static function findById(int $id, $guardName = null): RoleContract
    {
        $guardNameAttribute = config('permission.column_names.roles_guard_name_key');

        $guardName = $guardName ?? Guard::getDefaultName(static::class);

        $role = static::where('id', $id)->where($guardNameAttribute, $guardName)->first();

        if (! $role) {
            throw RoleDoesNotExist::withId($id);
        }

        return $role;
    }

    /**
     * Find or create role by its name (and optionally guardName).
     *
     * @param string $name
     * @param string|null $guardName
     *
     * @return \Spatie\Permission\Contracts\Role
     */
    public static function findOrCreate(string $name, $guardName = null): RoleContract
    {
        $nameAttribute = config('permission.column_names.roles_name_key');
        $guardNameAttribute = config('permission.column_names.roles_guard_name_key');

        $guardName = $guardName ?? Guard::getDefaultName(static::class);

        $role = static::where($nameAttribute, $name)->where($guardNameAttribute, $guardName)->first();

        if (! $role) {
            return static::query()->create([$nameAttribute => $name, $guardNameAttribute => $guardName]);
        }

        return $role;
    }

    /**
     * Determine if the user may perform the given permission.
     *
     * @param string|Permission $permission
     *
     * @return bool
     *
     * @throws \Spatie\Permission\Exceptions\GuardDoesNotMatch
     */
    public function hasPermissionTo($permission): bool
    {
        $permissionClass = $this->getPermissionClass();

        if (is_string($permission)) {
            $permission = $permissionClass->findByName($permission, $this->getDefaultGuardName());
        }

        if (is_int($permission)) {
            $permission = $permissionClass->findById($permission, $this->getDefaultGuardName());
        }

        if (! $this->getGuardNames()->contains($permission->guard_name)) {
            throw GuardDoesNotMatch::create($permission->guard_name, $this->getGuardNames());
        }

        return $this->permissions->contains('id', $permission->id);
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
