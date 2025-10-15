# IS Project

app contains vulnerabilites  
  
the mutation engine checks dont work perfectly, FIX  
add attacks  
only web_honeypot working, ssh mutations yet to be made

### INSTRUCTIONS:

Run the following commands:

1. `python deploy_honeypot.py` while **Docker Desktop** is open, retrieve `PORT` number
2. `docker logs -f aass_web_honeypot` -> Shows logs
3. `python web_mutation.py`
4. Test benign requests:

```
# open homepage
curl -s "http://localhost:{PORT}/" | sed -n '1,10p'

# simple search
curl -s "http://localhost:{PORT}/search?query=test"

# greet
curl -s "http://localhost:{PORT}/greet?name=Bob"

```

5. Test harmful requests:

```
curl -s "http://localhost:{PORT}/search?query=%27+OR+%271%27=%271" -A "sqlmap/1.6"      # doesnt work yet

curl -s "http://localhost:8421/greet?g_xy34=%3Cscript%3Ealert(1)%3C/script%3E" -A "BurpSuite"       # doesnt work yet

for i in {1..6}; do
  curl -s -X POST "http://localhost:$(docker port aass_web_honeypot | sed -n '1p' | awk -F: '{print $2}')/login" \
    -d "username=admin&password=bad${i}" \
    -A "hydra" >/dev/null
  sleep 1
done
                                                # WORKS


```