<?php
use PHPUnit\Framework\TestCase;
use RBAC\Role;

class RBAC_Role_Test extends TestCase {
    public function testAllowAll(){
        $role = new Role('user_1');
        $role->allow('*', '*', '*');
        $t1 = $role->isAllowed('edit', 'user', '1');
        $this->assertSame($t1, true);
        $t2 = $role->isAllowed('edit', 'user', '*');
        $this->assertSame($t2, true);
        $t3 = $role->isAllowed('edit', '*', '*');
        $this->assertSame($t3, true);
        $t4 = $role->isAllowed('edit', 'user', '?');
        $this->assertSame($t4, true);
    }

    public function testAllowedAllActionsOnOneResource(){
        $role = new Role('user_2');
        $role->allow('*', 'user', '*');

        $t1 = $role->isAllowed('view', 'group', '1');
        $this->assertNull($t1);
        $t1 = $role->isAllowed('edit', 'user', '1');
        $this->assertSame($t1, true);
        $t2 = $role->isAllowed('edit', 'user', '*');
        $this->assertSame($t2, true);
        $t3 = $role->isAllowed('edit', '*', '*');
        $this->assertSame($t3, null);
        $t4 = $role->isAllowed('edit', 'user', '?');
        $this->assertSame($t4, true);
    }

    public function testAllowedAllActionOnOneResourceID(){
        $role = new Role('user_2');
        $role->allow('*', 'user', '1');

        $t1 = $role->isAllowed('view', 'group', '1');
        $this->assertNull($t1);
        $t1 = $role->isAllowed('edit', 'user', '1');
        $this->assertSame($t1, true);
        $t2 = $role->isAllowed('edit', 'user', '*');
        $this->assertSame($t2, null);
        $t3 = $role->isAllowed('edit', '*', '*');
        $this->assertSame($t3, null);
        $t4 = $role->isAllowed('edit', 'user', '?');
        $this->assertSame($t4, true);
    }

    public function testAllowedOneActionOnOneResourceID(){
        $role = new Role('user_2');
        $role->allow('view', 'user', '1');

        $t1 = $role->isAllowed('view', 'group', '1');
        $this->assertNull($t1);
        $t1 = $role->isAllowed('edit', 'user', '1');
        $this->assertSame($t1, null);
        $t2 = $role->isAllowed('edit', 'user', '*');
        $this->assertSame($t2, null);
        $t3 = $role->isAllowed('edit', '*', '*');
        $this->assertSame($t3, null);
        $t4 = $role->isAllowed('edit', 'user', '?');
        $this->assertSame($t4, null);
        $this->assertNull($t1);
        $t1 = $role->isAllowed('view', 'user', '1');
        $this->assertSame($t1, true);
        $t2 = $role->isAllowed('view', 'user', '*');
        $this->assertSame($t2, null);
        $t3 = $role->isAllowed('view', '*', '*');
        $this->assertSame($t3, null);
        $t4 = $role->isAllowed('view', 'user', '?');
        $this->assertSame($t4, true);
    }

    public function testInherites(){
        $role_a = new Role('admin');
        $role = new Role('user');
        $role_a->allow('*', '*', '*');
        $role->inherite($role_a);

        $t1 = $role->isAllowed('edit', 'user', '1');
        $this->assertSame($t1, true);
        $t2 = $role->isAllowed('edit', 'user', '*');
        $this->assertSame($t2, true);
        $t3 = $role->isAllowed('edit', '*', '*');
        $this->assertSame($t3, true);
        $t4 = $role->isAllowed('edit', 'user', '?');
        $this->assertSame($t4, true);

        $role_g = new Role('group');
        $role_ug = new Role('user_g');
        $role_g->allow('view', 'user', '1');
        $role_ug->inherite($role_g);

        $t1 = $role_ug->isAllowed('view', 'group', '1');
        $this->assertNull($t1);
        $t1 = $role_ug->isAllowed('edit', 'user', '1');
        $this->assertSame($t1, null);
        $t2 = $role_ug->isAllowed('edit', 'user', '*');
        $this->assertSame($t2, null);
        $t3 = $role_ug->isAllowed('edit', '*', '*');
        $this->assertSame($t3, null);
        $t4 = $role_ug->isAllowed('edit', 'user', '?');
        $this->assertSame($t4, null);
        $this->assertNull($t1);
        $t1 = $role_ug->isAllowed('view', 'user', '1');
        $this->assertSame($t1, true);
        $t2 = $role_ug->isAllowed('view', 'user', '*');
        $this->assertSame($t2, null);
        $t3 = $role_ug->isAllowed('view', '*', '*');
        $this->assertSame($t3, null);
        $t4 = $role_ug->isAllowed('view', 'user', '?');
        $this->assertSame($t4, true);
    }

    public function testMultipleInherites(){
        $role_g1 = new Role('group1');
        $role_g2 = new Role('group2');
        $role_ug = new Role('user_g');
        $role_g1->allow('view', 'user', '1');
        $role_g2->allow('*', 'group', '*');
        $role_ug->inherite($role_g1);
        $role_ug->inherite($role_g2);

        $t1 = $role_ug->isAllowed('view', 'category', '1');
        $this->assertNull($t1);
        $t1 = $role_ug->isAllowed('edit', 'user', '1');
        $this->assertSame($t1, null);
        $t2 = $role_ug->isAllowed('edit', 'user', '*');
        $this->assertSame($t2, null);
        $t3 = $role_ug->isAllowed('edit', '*', '*');
        $this->assertSame($t3, null);
        $t4 = $role_ug->isAllowed('edit', 'user', '?');
        $this->assertSame($t4, null);
        $this->assertNull($t1);
        $t1 = $role_ug->isAllowed('view', 'user', '1');
        $this->assertSame($t1, true);
        $t2 = $role_ug->isAllowed('view', 'user', '*');
        $this->assertSame($t2, null);
        $t3 = $role_ug->isAllowed('view', '*', '*');
        $this->assertSame($t3, null);
        $t4 = $role_ug->isAllowed('view', 'user', '?');
        $this->assertSame($t4, true);



        $t1 = $role_ug->isAllowed('view', 'user', '5');
        $this->assertNull($t1);
        $t1 = $role_ug->isAllowed('edit', 'group', '1');
        $this->assertSame($t1, true);
        $t2 = $role_ug->isAllowed('edit', 'group', '*');
        $this->assertSame($t2, true);
        $t3 = $role_ug->isAllowed('edit', '*', '*');
        $this->assertSame($t3, null);
        $t4 = $role_ug->isAllowed('edit', 'group', '?');
        $this->assertSame($t4, true);
    }

    public function testParseResourceInfo(){
        $group = new Role('author');
        $group->allow('*', 'book', 1);
        $group->allow('view', 'article', '*');
        $user = new Role('user');
        $user->allow('view', 'book', 3);
        $user->allow('view', 'book', 4);
        $user->deny('view', 'book', 5);
        $user->inherite($group);

        $result = $user->parseResourceInfo('book', 'view');
        $this->assertCount(3, $result['allowed']);
        foreach ($result['allowed'] as $value) {
            $this->assertContains($value, array(1,3,4));
        }
        $this->assertEquals($result['denied'], array(5));

        $result = $user->parseResourceInfo('article', 'view');
        $this->assertEquals($result['allowed'], array('*'));
        $this->assertEquals($result['denied'], array());

        $result = $user->parseResourceInfo('category', 'view');
        $this->assertEquals($result['allowed'], array());
        $this->assertEquals($result['denied'], array());

    }

    public function testSpecificRole(){
        $group = new Role('admin');
        $group->allow('*', '*', '*');
        $role = new Role('user');
        $role->specificRole($group, 'project', '1');

        $t = $role->isAllowed('edit', 'project', '1');
        $this->assertSame($t, true);

        $t = $role->isAllowed('create', 'project');
        $this->assertSame($t, null);

        $t = $role->isAllowed('view', 'project', '2');
        $this->assertSame($t, null);

        $t = $role->isAllowed('delete', 'user', '1');
        $this->assertSame($t, null);
    }
}
