<?php

namespace Spatie\Permission\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Collection;
use Spatie\Permission\Models\Role;
use Spatie\Permission\Models\Permission;

class Show extends Command
{
    protected $signature = 'permission:show
            {guard? : The name of the guard}
            {style? : The display style (default|borderless|compact|box)}';

    protected $description = 'Show a table of roles and permissions per guard';

    protected $permissionsNameAttribute;

    protected $permissionsGuardNameAttribute;

    protected $rolesNameAttribute;

    protected $rolesGuardNameAttribute;

    public function handle()
    {
        // Database column names
        $this->permissionsNameAttribute = config('permission.column_names.permissions_name_key');
        $this->permissionsGuardNameAttribute = config('permission.column_names.permissions_guard_name_key');
        $this->rolesNameAttribute = config('permission.column_names.roles_name_key');
        $this->rolesGuardNameAttribute = config('permission.column_names.roles_guard_name_key');

        $style = $this->argument('style') ?? 'default';
        $guard = $this->argument('guard');

        if ($guard) {
            $guards = Collection::make([$guard]);
        } else {
            $guards = Permission::pluck(
                $this->permissionsGuardNameAttribute
            )->merge(Role::pluck(
                $this->rolesGuardNameAttribute
            ))->unique();
        }

        foreach ($guards as $guard) {
            $this->info("Guard: $guard");

            $roles = Role::where($this->rolesGuardNameAttribute, $guard)->orderBy($this->rolesNameAttribute)->get()->mapWithKeys(function (Role $role) {
                return [$role->name => $role->permissions->pluck($this->permissionsNameAttribute)];
            });

            $permissions = Permission::where($this->permissionsGuardNameAttribute, $guard)
                ->orderBy($this->permissionsNameAttribute)
                ->pluck($this->permissionsNameAttribute);

            $body = $permissions->map(function ($permission) use ($roles) {
                return $roles->map(function (Collection $role_permissions) use ($permission) {
                    return $role_permissions->contains($permission) ? ' ✔' : ' ·';
                })->prepend($permission);
            });

            $this->table(
                $roles->keys()->prepend('')->toArray(),
                $body->toArray(),
                $style
            );
        }
    }
}
