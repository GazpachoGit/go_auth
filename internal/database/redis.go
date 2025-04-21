package database

import (
	"fmt"
	"log"

	"github.com/go-redis/redis"
)

type CacheDB struct {
	DB *redis.Client
}

func NewCacheDB(host, port string) *CacheDB {
	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", host, port),
		Password: "predis",
		DB:       0,
	})
	_, err := rdb.Ping().Result()
	if err != nil {
		log.Fatalf("Redis connection failed: %v", err)
	}
	return &CacheDB{DB: rdb}
}
