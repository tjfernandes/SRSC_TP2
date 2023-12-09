#!/bin/sh

APP_KEY="xvub6434q4sk2ga"
APP_SECRET="tzqhgxazc5xt8l2"
ACCESS_CODE=$1

RESPONSE=$(curl --silent --location --request POST 'https://api.dropboxapi.com/oauth2/token' \
-u "$APP_KEY:$APP_SECRET" \
-H 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode "code=$ACCESS_CODE" \
--data-urlencode 'grant_type=authorization_code')

if echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('access_token', None))" > /dev/null
then
    ACCESS_TOKEN=$(echo $RESPONSE | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")
    echo $ACCESS_TOKEN
else
    echo "The access code has expired or is invalid."
fi