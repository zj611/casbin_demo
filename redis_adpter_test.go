package main

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	//redisAdapter "github.com/mlsen/casbin-redis-adapter/v2"
	redisAdapter "github.com/casbin/redis-adapter/v2"
	"testing"
)

func TestRedisAdapter(t *testing.T)  {

	//adapter, err := redisAdapter.NewFromURL("redis://:123@localhost:6380/0")
	//if err != nil{
	//	panic(err)
	//}

	adapter := redisAdapter.NewAdapterWithPassword("tcp","localhost:6380","123")


	enforcer, err := casbin.NewEnforcer("model.conf", adapter)
	if err != nil{
		panic(err)
	}
	enforcer.EnableAutoSave(true)

	// Load policy from redis
	enforcer.LoadPolicy()

	enforcer.AddNamedPolicy("p", []string{"sub1", "obj1","on"})
	fmt.Println(enforcer.Enforce("sub1", "obj1","on"))

	sub2 := `role::35046358490550272
	expr 855534449 + 870448142`
	enforcer.AddNamedPolicy("p", []string{sub2, "obj2","on"})

	fmt.Println(enforcer.Enforce("apikey::555", "uriid::11211111121", "on"))
	//error: false invalid policy size: expected 3, got 1, pvals: [role::35046358490550272]
}