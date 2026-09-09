# Auth Testing Playbook — Groupe Huvig

## Step 1: MongoDB verification
```
mongosh
use test_database
db.users.find({role: "admin"}).pretty()
```
Verify: bcrypt hash starts with `$2b$`, unique index on users.email, index on login_attempts.identifier.

## Step 2: API testing
```
curl -c cookies.txt -X POST $API/api/auth/login -H "Content-Type: application/json" -d '{"email":"admin@groupehuvig.fr","password":"GHV-Admin-2026!"}'
curl -b cookies.txt $API/api/auth/me
curl -b cookies.txt $API/api/admin/stats
```
Login returns the admin user and sets an httpOnly `access_token` cookie. /me and /admin/stats must succeed with the cookie and return 401 without it.
