# php-rbac
A simple and portable ACL using role based access control (RBAC) written in PHP

### Define role's permissions

```php
<?php
use RBAC\Role;

// Allow permission on a resource
$role = new Role($role_name);
$role->allow($action, $resource_type, $resource_id);

// It support * wildcard character
// Allow all action on all items of all resources
$role->allow('*', '*', '*');

// Allow all action on all items of a specific resource
$role->allow('*', 'article', '*');

// Allow one action on all items of a specific resource
$role->allow('view', 'article', '*');

// Allow all action on one item of a specific resource
$role->allow('*', 'article', '1');

// Allow one action on one item of a specific resource
$role->allow('delete', 'article', '1');

```

### Check role's permissions
```php
<?php
use RBAC\Role;

// Allow permission on a resource
$role = new Role($role_name);
$role->allow('view', 'article', '1');

// Check permissions
$role->isAllowed('view', 'article', '1'); // True
$role->isAllowed('view', 'article', '2'); // False
$role->isAllowed('view', 'article', '*'); // False

// It support ? wildcard character
// Check if $role can view any article 
$role->isAllowed('view', 'article', '?'); // True

$role->isAllowed('create', 'article'); // False

```

### Inherites from other roles

You can inherite permissions from other role

```php
<?php
use RBAC\Role;

// Allow permission on a resource
$admin_role = new Role('group_admin');
$admin_role->allow('*', '*', '*');

$mod_role = new Role('group_moderator');
$mod_role->allow('*', 'article', '*');

$u1_role = new Role('user_1');
$u1_role->inherite($admin_role);
$u2_role = new Role('user_2');
$u2_role->inherite($mod_role);

$u1->isAllowed('create', 'article'); // True
$u2->isAllowed('delete', 'article', '1'); // True
$u2->isAllowed('create', 'category'); // False

```

You can inherite from other role on a specific item as well, using specificRole function

```php
<?php
use RBAC\Role;

// Allow permission on a resource
$admin_role = new Role('group_admin');
$admin_role->allow('*', '*', '*');

$mod_role = new Role('group_moderator');
$mod_role->allow('*', 'article', '*');

// user_1 has admin permission on article with ID=3 only
$u1_role = new Role('user_1');
$u1_role->specificRole($admin_role, 'article', '3');

$u1->isAllowed('edit', 'article', '3'); // True
$u1->isAllowed('delete', 'article', '3'); // True
$u1->isAllowed('edit', 'article', '1'); // False

```

### Parse resource information

Sometime you need to know which resource IDs that a role has a specific permission on it

```php
<?php
use RBAC\Role;

$group = new Role('author');
$group->allow('*', 'book', 1);
$group->allow('view', 'article', '*');
$user = new Role('user');
$user->allow('view', 'book', 3);
$user->allow('view', 'book', 4);
$user->deny('view', 'book', 5);
$user->inherite($group);

// check what book IDs user can view or denied to view
$result = $user->parseResourceInfo('book', 'view');
assertCount(3, $result['allowed']);
foreach ($result['allowed'] as $value) {
    assertContains($value, array(1,3,4));
}
assertEquals($result['denied'], array(5));

// check what article IDs user can view or denied to view
$result = $user->parseResourceInfo('article', 'view');
assertEquals($result['allowed'], array('*'));
assertEquals($result['denied'], array());

// check what category IDs user can view or denied to view
$result = $user->parseResourceInfo('category', 'view');
assertEquals($result['allowed'], array());
assertEquals($result['denied'], array());
```
