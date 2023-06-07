#!/bin/bash

# clears the database and redis cache

sqlx database drop
sqlx database create
sqlx migrate run
redis-cli FLUSHALL