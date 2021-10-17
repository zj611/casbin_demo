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
		DSN: "root:root@tcp(0.0.0.0:3306)/test?charset=utf8mb4&parseTime=True&loc=Local", // data source name, refer https://github.com/go-sql-driver/mysql#dsn-data-source-name
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
	e, _ := casbin.NewEnforcer("model.conf", a)
	e.EnableAutoSave(false)

	// Load the policy from DB.
	e.LoadPolicy()

	// Modify the policy.
	var k [][]string
	k = append(k, []string{"aqaq", "data1", "read"})
	e.AddPolicies(k)
	//e.RemovePolicy(k[0])
	// 向当前命名策略添加授权规则。 如果规则已经存在，函数返回false，并且不会添加规则。 否则，函数通过添加新规则并返回true
	//e.AddNamedPolicy("p", "role::1", "stra::1", "on")
	//e.AddNamedPolicy("p", "role::1", "stra::2", "on")
	//e.AddNamedPolicy("p", "role::1", "svcg::1", "on")
	//e.AddNamedPolicy("p", "role::2", "svcg::2", "on")
	//e.AddNamedPolicy("p", "role::3", "svcg::3", "on")

	//将命名角色继承规则添加到当前策略。 如果规则已经存在，函数返回false，并且不会添加规则。 否则，函数通过添加新规则并返回true
	//e.AddNamedGroupingPolicy("g", "apikey::1", "role::1")
	//e.AddNamedGroupingPolicy("g", "apikey::11", "role::1")
	//e.AddNamedGroupingPolicy("g", "apikey::2", "role::2")
	//
	//e.AddNamedGroupingPolicy("g2", "uriid::1", "svcg::1")
	//e.AddNamedGroupingPolicy("g2", "uriid::2", "svcg::2")
	//
	//e.AddNamedGroupingPolicy("g2", "uriid::1", "stra::1")
	//e.AddNamedGroupingPolicy("g2", "uriid::2", "stra::2")
	// Save the policy back to DB.
	//err = e.SavePolicy()

	// Check the permission.

	fmt.Println( e.Enforce("apikey::1", "svcg::1", "on"))
	fmt.Println(e.EnforceEx("apikey::1", "svcg::1", "on"))

	fmt.Println( e.Enforce("apikey::1", "uriid::1", "on"))
	fmt.Println( e.Enforce("apikey::1", "stra::1", "on"))
	fmt.Println( e.Enforce("apikey::1", "stra::2", "on"))
	fmt.Println( e.Enforce("apikey::2", "stra::1", "on"))



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
	Ptype string `gorm:"type:varchar(100);uniqueIndex:unique_index"`
	V0    string `gorm:"type:varchar(100);uniqueIndex:unique_index"`
	V1    string `gorm:"type:varchar(100);uniqueIndex:unique_index"`
	V2    string `gorm:"type:varchar(100);uniqueIndex:unique_index"`
	V3    string `gorm:"type:varchar(100);uniqueIndex:unique_index"`
	V4    string `gorm:"type:varchar(100);uniqueIndex:unique_index"`
	V5    string `gorm:"type:varchar(100);uniqueIndex:unique_index"`
}
