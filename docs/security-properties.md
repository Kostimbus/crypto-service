DATA=$(printf "hello" | base64 -w0)
curl -s localhost:8000/sign   -H 'content-type: application/json' -d "{\"data\":\"$DATA\"}"
curl -s localhost:8000/encrypt -H 'content-type: application/json' -d "{\"data\":\"$DATA\"}"
