package main

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"gorm.io/driver/mysql"
	//"github.com/jinzhu/gorm"
	"gorm.io/gorm"
)

func main() {
	db, err := gorm.Open(mysql.New(mysql.Config{
		DSN:                       "root:root@tcp(0.0.0.0:3306)/test?charset=utf8mb4&parseTime=True&loc=Local", // data source name, refer https://github.com/go-sql-driver/mysql#dsn-data-source-name
		DefaultStringSize:         256,                                                                         // add default size for string fields, by default, will use db type `longtext` for fields without size, not a primary key, no index defined and don't have default values
		DisableDatetimePrecision:  true,                                                                        // disable datetime precision support, which not supported before MySQL 5.6
		DontSupportRenameIndex:    true,                                                                        // drop & create index when rename index, rename index not supported before MySQL 5.7, MariaDB
		DontSupportRenameColumn:   true,                                                                        // use change when rename column, rename rename not supported before MySQL 8, MariaDB
		SkipInitializeWithVersion: false,                                                                       // smart configure based on used version
	}), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}

	// Initialize a Gorm adapter and use it in a Casbin enforcer:
	// The adapter will use an existing gorm.DB instnace.
	a, _ := gormadapter.NewAdapterByDBWithCustomTable(db, &CasbinRule{})
	e, _ := casbin.NewEnforcer("model.conf", a)
	e.EnableAutoSave(true)

	// 向当前命名策略添加授权规则。 如果规则已经存在，函数返回false，并且不会添加规则。 否则，函数通过添加新规则并返回true
	e.AddNamedPolicy("p", "role::1", "stra::1", "on")
	e.AddNamedPolicy("p", "role::1", "stra::2", "on")
	e.AddNamedPolicy("p", "role::1", "svcg::1", "on")
	e.AddNamedPolicy("p", "role::2", "svcg::2", "on")
	e.AddNamedPolicy("p", "role::3", "svcg::3", "on")


	//将命名角色继承规则添加到当前策略。 如果规则已经存在，函数返回false，并且不会添加规则。 否则，函数通过添加新规则并返回true
	e.AddNamedGroupingPolicy("g", "admin::1", "role::111")
	e.AddNamedGroupingPolicy("g", "apikey::1", "role::1")
	e.AddNamedGroupingPolicy("g", "apikey::11", "role::1")
	e.AddNamedGroupingPolicy("g", "apikey::2", "role::2")

	e.AddNamedGroupingPolicy("g2", "uriid::1", "svcg::1")
	e.AddNamedGroupingPolicy("g2", "uriid::2", "svcg::2")

	e.AddNamedGroupingPolicy("g2", "uriid::1", "stra::1")
	e.AddNamedGroupingPolicy("g2", "uriid::11", "stra::1")
	e.AddNamedGroupingPolicy("g2", "uriid::2", "stra::2")

	// Load the policy from DB.
	e.LoadPolicy()

	// Modify the policy.
	//fmt.Println(e.GetUsersForRole("role::1"))
	//fmt.Println(e.GetUsersForRole("stra::1"))
	//fmt.Println(e.GetImplicitUsersForRole("stra::1"))
	check1(e, "admin::1", "stra::1", "on")
	check1(e, "apikey::1", "svcg::2", "on")
	//=====================用户查询角色 "apikey::1"====================
	//fmt.Println(e.GetRolesForUser("apikey::1"))
	//===========================================================

	//=====================根据"apikey::1"找到服务组id====================
	//fmt.Println(e.GetImplicitPermissionsForUser("apikey::1")) //[[role::1 stra::1 on] [role::1 stra::2 on] [role::1 svcg::1 on]]
	//===========================================================


	//=====================根据"role::1"找到apikey====================
	//fmt.Println(e.GetUsersForRole("role::1")) //[[role::1 stra::1 on] [role::1 stra::2 on] [role::1 svcg::1 on]]
	//===========================================================



	//=====================删除单一的用户-角色 "apikey::1"====================
	//e.DeleteRoleForUser("apikey::2", "role::2")
	//===========================================================

	//=====================删除角色"role::1"====================
	//e.DeleteRole("role::1")//一次性全部删除权限关系,和归属关系
	//===========================================================

	//=====================删除用户"apikey::1"====================
	//e.DeleteUser("apikey::1") //一次性全部删除权限关系,和归属关系
	//===========================================================

	//=====================删除资源"stra::1"====================
	//删除资源"stra::1"
	//l,_ := e.GetImplicitUsersForRole("stra::1")	//①删除对应的权限关系
	//e.DeletePermission("stra::1")
	//for _,v := range l{	//②删除归属关系
	//	fmt.Println("for",l,v)
	//	//_, _ = e.DeleteRoleForUser(v1, "stra::1")
	//	e.RemoveNamedGroupingPolicy("g2",v,"stra::1")
	//}
	//===========================================================

	// Save the policy back to DB.
	//err = e.SavePolicy()

	// Check the permission.

	fmt.Println(e.Enforce("apikey::1", "svcg::1", "on"))
	fmt.Println(e.EnforceEx("apikey::1", "svcg::1", "on"))

	fmt.Println(e.Enforce("apikey::1", "uriid::1", "on"))
	fmt.Println(e.Enforce("apikey::1", "stra::1", "on"))
	fmt.Println(e.Enforce("apikey::1", "stra::2", "on"))
	fmt.Println(e.Enforce("apikey::2", "stra::1", "on"))
}

func check1(e *casbin.Enforcer, sub, obj, act string) {
	ok, _ := e.Enforce(sub, obj, act)
	if ok {
		fmt.Printf("%s CAN %s %s\n", sub, act, obj)
	} else {
		fmt.Printf("%s CANNOT %s %s\n", sub, act, obj)
	}
}

func check(e *casbin.Enforcer, app, role, svcGroup, act string) {
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
	Ptype string `gorm:"type:varchar(100);uniqueIndex:unique_index"`
	V0    string `gorm:"type:varchar(100);uniqueIndex:unique_index"`
	V1    string `gorm:"type:varchar(100);uniqueIndex:unique_index"`
	V2    string `gorm:"type:varchar(100);uniqueIndex:unique_index"`
	V3    string `gorm:"type:varchar(100);uniqueIndex:unique_index"`
	V4    string `gorm:"type:varchar(100);uniqueIndex:unique_index"`
	V5    string `gorm:"type:varchar(100);uniqueIndex:unique_index"`
}
