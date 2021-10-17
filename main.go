package main

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"gorm.io/driver/mysql"
	//"github.com/jinzhu/gorm"
	"gorm.io/gorm"
	"log"
)

func main() {

	//db, _ := gorm.Open("mysql","root:root@tcp(localhost:3306)/test?charset=utf8&parseTime=true")
	db, err := gorm.Open(mysql.New(mysql.Config{
		DSN: "root:123@tcp(0.0.0.0:3306)/data?charset=utf8mb4&parseTime=True&loc=Local", // data source name, refer https://github.com/go-sql-driver/mysql#dsn-data-source-name
		DefaultStringSize: 256, // add default size for string fields, by default, will use db type `longtext` for fields without size, not a primary key, no index defined and don't have default values
		DisableDatetimePrecision: true, // disable datetime precision support, which not supported before MySQL 5.6
		DontSupportRenameIndex: true, // drop & create index when rename index, rename index not supported before MySQL 5.7, MariaDB
		DontSupportRenameColumn: true, // use change when rename column, rename rename not supported before MySQL 8, MariaDB
		SkipInitializeWithVersion: false, // smart configure based on used version
	}), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	// Initialize a Gorm adapter and use it in a Casbin enforcer:
	// The adapter will use an existing gorm.DB instnace.
	a, _ := gormadapter.NewAdapterByDBWithCustomTable(db, &CasbinRule{})
	e, _ := casbin.NewEnforcer("rbac_model.conf", a)

	// Load the policy from DB.
	e.LoadPolicy()

	// Modify the policy.
	var k [][]string
	k = append(k, []string{"alice", "data1", "read"})
	e.AddPolicies(k)


	// Check the permission.
	bo1, _ := e.Enforce("alice", "data1", "read")
	fmt.Println("bo1",bo1)

	e.RemovePolicy(k[0])

	// Check the permission.
	bo1, _ = e.Enforce("alice", "data1", "read")
	fmt.Println("bo1",bo1)

	// Save the policy back to DB.
	e.SavePolicy()


	//测试用户-应用-角色-服务组关系
	e1, err := casbin.NewEnforcer("./model.conf", "./policy.csv")
	if err != nil {
		log.Fatalf("NewEnforecer failed:%v\n", err)
	}
	//p, role1, svcGroup1, on
	check(e1, "app1", "role1", "svcGroup1","on")

	//https://casbin.org/docs/zh-CN/rbac-api
	d, _ := e1.GetImplicitResourcesForUser("app1", "")
	fmt.Println("GetImplicitResourcesForUser: ",d)

	d,_ = e1.GetImplicitPermissionsForUser("app1","")
	fmt.Println("GetImplicitPermissionsForUser: ",d)

	d1, _ := e1.GetRolesForUser("app1")
	fmt.Println("GetRolesForUser: ",d1)
	//[role1]

	d = e1.GetPermissionsForUser("app1")
	fmt.Println("GetPermissionsForUser: ",d)
	//[]

	d, _ = e1.GetImplicitPermissionsForUser("app1")
	fmt.Println("GetImplicitPermissionsForUser: ",d)
	// [[role1 svcGroup1 on] [role1 svcGroup1 on]]

	hasNamedPolicy := e1.HasNamedPolicy("p2", "role1", "svcGroup1", "on")
	fmt.Println(hasNamedPolicy)

	//e.GetFilteredGroupingPolicy()

	// 确定是否存在授权规则
	hasPolicy := e1.HasPolicy("app1", "role1", "on")
	fmt.Println(hasPolicy)

	//uu := e.HasPermissionForUser("app1")
	//fmt.Println(uu)



	fmt.Println(e1.GetImplicitUsersForRole("role1"))
	//[app1] <nil>
	fmt.Println(e1.GetImplicitUsersForPermission("p","svcGroup1","on"))
	//[app1] <nil>
}


func check(e *casbin.Enforcer, app, role, svcGroup,act string) {
	ok, _ := e.Enforce(app, role, svcGroup, act)
	if ok {
		fmt.Printf("%s CAN %s %s\n", app, act, role)
	} else {
		fmt.Printf("%s CANNOT %s %s\n", app, act, role)
	}
}

// Increase the column size to 512.
type CasbinRule struct {
	ID    uint   `gorm:"primaryKey;autoIncrement"`
	Ptype string `gorm:"type:varchar(256);uniqueIndex:unique_index"`
	V0    string `gorm:"type:varchar(256);uniqueIndex:unique_index"`
	V1    string `gorm:"type:varchar(256);uniqueIndex:unique_index"`
	V2    string `gorm:"type:varchar(256);uniqueIndex:unique_index"`
	V3    string `gorm:"type:varchar(256);uniqueIndex:unique_index"`
	V4    string `gorm:"type:varchar(256);uniqueIndex:unique_index"`
	V5    string `gorm:"type:varchar(256);uniqueIndex:unique_index"`
}
