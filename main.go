package main

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	"log"
)

func check(e *casbin.Enforcer, app, role, svcGroup,act string) {
	ok, _ := e.Enforce(app, role, svcGroup, act)
	if ok {
		fmt.Printf("%s CAN %s %s\n", app, act, role)
	} else {
		fmt.Printf("%s CANNOT %s %s\n", app, act, role)
	}
}

func main() {
	e, err := casbin.NewEnforcer("./model.conf", "./policy.csv")
	if err != nil {
		log.Fatalf("NewEnforecer failed:%v\n", err)
	}
	//p, role1, svcGroup1, on
	check(e, "app1", "role1", "svcGroup1","on")

	//https://casbin.org/docs/zh-CN/rbac-api
	d, _ := e.GetImplicitResourcesForUser("app1", "")
	fmt.Println("GetImplicitResourcesForUser: ",d)

	d,_ = e.GetImplicitPermissionsForUser("app1","")
	fmt.Println("GetImplicitPermissionsForUser: ",d)

	d1, _ := e.GetRolesForUser("app1")
	fmt.Println("GetRolesForUser: ",d1)
	//[role1]

	d = e.GetPermissionsForUser("app1")
	fmt.Println("GetPermissionsForUser: ",d)
	//[]

	d, _ = e.GetImplicitPermissionsForUser("app1")
	fmt.Println("GetImplicitPermissionsForUser: ",d)
	// [[role1 svcGroup1 on] [role1 svcGroup1 on]]



	//d11 := e.GetNamedGroupingPolicy("app1")
	//fmt.Println("GetNamedGroupingPolicy: ",d11)


	hasNamedPolicy := e.HasNamedPolicy("p2", "role1", "svcGroup1", "on")
	fmt.Println(hasNamedPolicy)

	//e.GetFilteredGroupingPolicy()

	// 确定是否存在授权规则
	hasPolicy := e.HasPolicy("app1", "role1", "on")
	fmt.Println(hasPolicy)

	//uu := e.HasPermissionForUser("app1")
	//fmt.Println(uu)
}