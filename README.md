### go usermgr
#### init
psql usermgr -f schema.sql 
#### create admin user
go run ./cmd/seed $(ARGS)
#### docker run
docker run  -d --name usermgr --network host --env-file .env  ghcr.io/jesse20250808/usermgr:latest
####
