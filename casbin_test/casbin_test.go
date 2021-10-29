package casbin_test

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"

	//rediswatcher "github.com/casbin/redis-watcher/v2"
	watcher "github.com/billcobbler/casbin-redis-watcher/v2"
	"gorm.io/driver/mysql"
	"testing"

	//"github.com/jinzhu/gorm"
	"gorm.io/gorm"

	//redis watcher
	"log"

	//测试效果增加休眠
	"time"
)

func updateCallback(msg string) {
	log.Println("call back:", msg)

}

func AddNamedPolicy1(e *casbin.Enforcer) error {
	// 向当前命名策略添加授权规则。 如果规则已经存在，函数返回false，并且不会添加规则。 否则，函数通过添加新规则并返回true
	e.AddNamedPolicy("p", "role::1", "stra::11", "on")
	fmt.Println("----------------------------AddNamedPolicy1")
	return nil

}

func AddPolicy1(e *casbin.Enforcer) error {
	// 向当前命名策略添加授权规则。 如果规则已经存在，函数返回false，并且不会添加规则。 否则，函数通过添加新规则并返回true
	e.AddPolicy("p", "apikey::100", "stra::2", "on")
	fmt.Println("----------------------------AddPolicy1")
	return nil
}

func AddPolicies(e *casbin.Enforcer) error {
	rules := [][]string{
		[]string{"apikey::jack", "data4", "on"},
		[]string{"apikey::katy", "data4", "on"},
		[]string{"apikey::leyo", "data4", "on"},
		[]string{"apikey::ham", "data4", "on"},
	}
	areRulesAdded, _ := e.AddPolicies(rules)
	fmt.Println("----------------------------areRulesAdded:", areRulesAdded)

	return nil
}

func TestWatcher(t *testing.T) {
	//create watcher
	// Initialize the watcher.
	// Use the Redis host as parameter.
	//var op []watcher.WatcherOption
	//h := watcher.WatcherOptions{
	//	Channel: "/casbin",
	//}

	w, err := watcher.NewWatcher("127.0.0.1:6380",
		watcher.Channel("/casbin"),
		watcher.Password("123"),
		watcher.IgnoreSelf(true),
	)
	if err != nil {
		panic(err)
	}

	//w, err := watcher.NewWatcher("localhost:6380", watcher.WatcherOptions{
	//	Options: redis.Options{
	//		Network:  "tcp",
	//		Password: "123",
	//	},
	//	Channel:    "/casbin",
	//	// Only exists in test, generally be true
	//	IgnoreSelf: false,
	//	//OptionalUpdateCallback: rediswatcher.CustomDefaultFunc(updateCallback),
	//})
	if err != nil {
		fmt.Println("error occur:", err.Error())
	}

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
	// Set the watcher for the enforcer.
	_ = w.SetUpdateCallback(updateCallback)

	err = e.SetWatcher(w)
	if err != nil {
		fmt.Println(err)
	}
	e.EnableAutoSave(true)
	// Load the policy from DB.
	e.LoadPolicy()

	// Set callback to local example

	e.EnableAutoNotifyWatcher(true)

	// _ = w.Update()
	// _ = w.UpdateForAddPolicy("1111","p", "role::1", "stra::1", "on")
	// _ = w.UpdateForRemovePolicy()
	// _ = w.UpdateForRemoveFilteredPolicy()
	// _ = w.UpdateForSavePolicy()

	//临时取消掉
	// Update the policy to test the effect.
	// You should see "[casbin rules updated]" in the log.
	// _ = e.SavePolicy()
	// // Only exists in test
	// fmt.Scanln()

	// AddNamedPolicy1(e)
	// AddPolicy1(e)
	// AddPolicies(e)

	fmt.Println("--------all done prepare to quit--------------------0")
	//time.Sleep(time.Duration(20) * time.Second)
	//return

	// e.AddPolicy("p", "apikey::12", "stra::2", "on")
	// _ = e.SavePolicy()
	//time.Sleep(time.Duration(10) * time.Second)

	e.AddNamedPolicy("p", "role::1", "stra::2", "on")

	time.Sleep(time.Duration(1) * time.Second)
	fmt.Println("----------------------------1")
	e.AddNamedPolicy("p", "role::1", "svcg::1", "on")
	time.Sleep(time.Duration(1) * time.Second)
	fmt.Println("----------------------------2")
	e.AddNamedPolicy("p", "role::2", "svcg::2", "on")
	time.Sleep(time.Duration(1) * time.Second)
	fmt.Println("----------------------------3")
	e.AddNamedPolicy("p", "role::3", "svcg::3", "on")
	time.Sleep(time.Duration(1) * time.Second)
	fmt.Println("----------------------------4")
	e.AddNamedPolicy("p", "apikey::100", "stra::1", "on")
	time.Sleep(time.Duration(1) * time.Second)
	fmt.Println("----------------------------5")
	e.AddNamedPolicy("p", "apikey::100", "svcg::1", "on")
	time.Sleep(time.Duration(1) * time.Second)
	fmt.Println("----------------------------6")
	//将命名角色继承规则添加到当前策略。 如果规则已经存在，函数返回false，并且不会添加规则。 否则，函数通过添加新规则并返回true
	e.AddNamedGroupingPolicy("g", "admin::1", "role::111")
	fmt.Println("----------------------------7")
	time.Sleep(time.Duration(1) * time.Second)
	e.AddNamedGroupingPolicy("g", "apikey::1", "role::1")
	fmt.Println("----------------------------8")
	time.Sleep(time.Duration(1) * time.Second)
	e.AddNamedGroupingPolicy("g", "apikey::11", "role::1")
	fmt.Println("----------------------------9")
	time.Sleep(time.Duration(1) * time.Second)
	e.AddNamedGroupingPolicy("g", "apikey::2", "role::2")
	fmt.Println("----------------------------10")
	time.Sleep(time.Duration(1) * time.Second)
	e.AddNamedGroupingPolicy("g", "apikey::100", "role::1")
	fmt.Println("----------------------------11")
	time.Sleep(time.Duration(1) * time.Second)

	e.AddNamedGroupingPolicy("g2", "uriid::1", "svcg::1")
	fmt.Println("----------------------------12")
	time.Sleep(time.Duration(1) * time.Second)
	e.AddNamedGroupingPolicy("g2", "uriid::2", "svcg::2")
	fmt.Println("----------------------------13")
	time.Sleep(time.Duration(1) * time.Second)

	e.AddNamedGroupingPolicy("g2", "uriid::1", "stra::1")
	fmt.Println("----------------------------14")
	time.Sleep(time.Duration(1) * time.Second)
	e.AddNamedGroupingPolicy("g2", "uriid::11", "stra::1")
	fmt.Println("----------------------------15")
	time.Sleep(time.Duration(1) * time.Second)
	e.AddNamedGroupingPolicy("g2", "uriid::2", "stra::2")
	fmt.Println("----------------------------16")
	time.Sleep(time.Duration(10) * time.Second)

	getRoleList, _ := e.GetRolesForUser("apikey::100")
	fmt.Println(getRoleList)

	for {
		fmt.Println("---all done, Sleep")
		time.Sleep(time.Duration(60) * time.Second)
	}

	return

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
