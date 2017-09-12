<?php
namespace RBAC;

class Role {
    const ALL = '*';
    const ANY = '?';
    protected $resources = array();
    protected $inherites = array();
    protected $specificRoles = array();
    protected $name = '';

    public function __construct($name){
        $this->name = $name;
    }

    public function getName(){
        return $this->name;
    }

    public function allow($action, $resource_type, $resource_id = Role::ALL){
        if(!isset($this->resources[$resource_type])){
            $this->resources[$resource_type] = array();
        }
        if(!isset($this->resources[$resource_type][$resource_id])){
            $this->resources[$resource_type][$resource_id] = array();
        }
        $this->resources[$resource_type][$resource_id][$action] = true;
    }

    public function deny($action, $resource_type, $resource_id = Role::ALL){
        if(!isset($this->resources[$resource_type])){
            $this->resources[$resource_type] = array();
        }
        if(!isset($this->resources[$resource_type][$resource_id])){
            $this->resources[$resource_type][$resource_id] = array();
        }
        $this->resources[$resource_type][$resource_id][$action] = false;
    }

    public function isAllowed($action, $resource_type, $resource_id = Role::ALL){
        $result = null;

        if( isset($this->resources[$resource_type]) ){
            $result = $this->check_resource($this->resources[$resource_type], $resource_id, $action);
        }
        if ( is_null($result) && isset($this->resources[self::ALL]) ) {
            $result = $this->check_resource($this->resources[self::ALL], $resource_id, $action);
        }
        if( is_null($result) ){
            foreach($this->specificRoles as $item){
                if($item['resource'] == $resource_type && $item['resource_id'] == $resource_id){
                    $result = $item['role']->isAllowed($action, $resource_type, $resource_id);
                }
            }
        }

        // check permissions from inherites
        if( is_null($result) ){
            foreach($this->inherites as $parent){
                $result = $parent->isAllowed($action, $resource_type, $resource_id);
                if( ! is_null($result) ){
                    return $result;
                }
            }
        }

        return $result;
    }

    public function parseResourceInfo($resource, $action){
        $result = array('allowed' => array(), 'denied' => array());

        if(isset($this->resources[$resource])){
            $this->parse_resource($this->resources[$resource], $action, $result);
        }

        if (isset($this->resources[self::ALL])){
            $this->parse_resource($this->resources[self::ALL], $action, $result);
        }

        foreach($this->inherites as $parent){
            $pr = $parent->parseResourceInfo($resource, $action);
            foreach($pr['allowed'] as $id){
                if(!in_array($id, $result['denied']) && !in_array($id, $result['allowed'])){
                    $result['allowed'][] = $id;
                }
            }
            foreach ($pr['allowed'] as $id) {
                if(!in_array($id, $result['denied']) && !in_array($id, $result['allowed'])){
                    $result['denied'][] = $id;
                }
            }
        }

        return $result;
    }

    public function specificRole(Role $role, $resource, $resource_id){
        $this->specificRoles[] = array(
            'resource_id' => $resource_id, 
            'resource' => $resource, 
            'role' => $role
        );
    }

    protected function check_resource($resource, $resource_id, $action){
        if(isset($resource[$resource_id])){
            return $this->check_resource_id($resource[$resource_id], $action);
        } else if ($resource_id == self::ANY){
            foreach ($resource as $id => $value) {
                $result = $this->check_resource_id($value, $action);
                if($result){
                    return true;
                }
            }
            return null;
        } else if(isset($resource[self::ALL])) {
            return $this->check_resource_id($resource[self::ALL], $action);
        }

        return null;
    }

    protected function check_resource_id($resource_id, $action){
        if( isset($resource_id[$action]) ){
            return $resource_id[$action];
        } else if (isset ($resource_id[self::ALL]) ){
            return $resource_id[self::ALL];
        }

        return null;
    }

    protected function parse_resource($resource, $action, array &$result){
        foreach($resource as $resource_id => $value){
            if( isset($value[$action]) ){
                if($value[$action]){
                    if(!in_array($resource_id, $result['allowed'])){
                        $result['allowed'][] = $resource_id;
                    }
                } else {
                    if(!in_array($resource_id, $result['denied'])){
                        $result['denied'][] = $resource_id;
                    }
                }
            }
            if(isset($value[self::ALL])){
                if($value[self::ALL]){
                    if(!in_array(self::ALL, $result['allowed'])){
                        $result['allowed'][] = $resource_id;
                    }
                } else {
                    if(!in_array(self::ALL, $result['denied'])){
                        $result['denied'][] = $resource_id;
                    }
                }
            }
        }
    }

    public function inherite(Role $role){
        $this->inherites[$role->getName()] = $role;
    }
}
