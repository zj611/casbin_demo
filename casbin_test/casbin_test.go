package casbin_test

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/go-redis/redis/v8"

	//rediswatcher "github.com/casbin/redis-watcher/v2"
	rediswatcher "casbin/my-redis-watcher"
	//watcher "github.com/billcobbler/casbin-redis-watcher/v2"
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

func TestWatcher(t *testing.T) {

	//w, err := watcher.NewWatcher("127.0.0.1:6380",
	//	watcher.Channel("/casbin"),
	//	watcher.Password("123"),
	//	watcher.IgnoreSelf(true),
	//)
	//if err != nil {
	//	panic(err)
	//}


	w, err := rediswatcher.NewWatcher("localhost:6380", rediswatcher.WatcherOptions{
		Options: redis.Options{
			Network:  "tcp",
			Password: "123",
		},
		Channel:    "/casbin",
		// Only exists in test, generally be true
		IgnoreSelf: true,
		//OptionalUpdateCallback: rediswatcher.CustomDefaultFunc(updateCallback),
	})


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
	w.Update()
	err = e.SetWatcher(w)
	if err != nil {
		fmt.Println(err)
	}
	e.EnableAutoSave(true)
	// Load the policy from DB.
	e.LoadPolicy()


	//-------增加权限-------
	e.AddNamedPolicy("p", "role::1", "stra::2", "on")
	time.Sleep(time.Duration(1) * time.Second)

	//-------删除权限-------
	e.RemoveNamedPolicy("p", "role::1", "stra::2", "on")
	time.Sleep(time.Duration(1) * time.Second)

	//-------增加组策略-------
	e.AddNamedGroupingPolicy("g", "admin::1", "role::111")
	time.Sleep(time.Duration(1) * time.Second)

	//-------删除组策略-------
	e.RemoveNamedGroupingPolicy("g", "admin::1", "role::111")
	time.Sleep(time.Duration(1) * time.Second)


	//-------更新权限策略  on 改为off-------暂时不行
	//oldPolicy := []string{"role::11", "stra::2", "on"}
	//newPolicy := []string{"role::11", "stra::2", "off"}
	//e.UpdateNamedPolicy("p",oldPolicy, newPolicy)
	//time.Sleep(time.Duration(1) * time.Second)


	return

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
