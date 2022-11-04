# BloodHoundCustomQueries

Useful custom queries. Inspired from:

- <https://github.com/ZephrFish/Bloodhound-CustomQueries>
- <https://github.com/CompassSecurity/BloodHoundQueries>
- <https://github.com/hausec/Bloodhound-Custom-Queries>
- <https://github.com/ly4k/Certipy>
- <https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/red-teaming/bloodhound/Handy-BloodHound-Cypher-Queries.md>

## Usage

```text
git clone https://github.com/zblurx/BloodHoundCustomQueries
cp BloodHoundCustomQueries/customqueries.json ~/.config/bloodhound/customqueries.json
```

or 

```text
git clone https://github.com/zblurx/BloodHoundCustomQueries
cd BloodHoundCustomQueries
make
```

## Queries

Generated with jq-fu:
```bash
cat customqueries.json | jq -r ' .queries[] | {"name":.name, "query":.queryList[].query} | "### \(.name) \n\n ```text\n\(.query)\n```\n\n"'
```

### List all owned computers

 ```text
MATCH (m:Computer) WHERE m.owned=TRUE RETURN m
```


### List all High Valued Targets

 ```text
MATCH (m) WHERE m.highvalue=TRUE RETURN m
```


### Find computers with owned Admins

 ```text
MATCH p=shortestPath((n:User {owned:true})-[r:AdminTo|MemberOf*1..]->(c:Computer)) return p
```


### Shortest path from owned users with permissions against GPOs

 ```text
MATCH p=shortestPath((u:User {owned:true})-[r:MemberOf|AddSelf|WriteSPN|AddKeyCredentialLink|AddMember|AllExtendedRights|ForceChangePassword|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(g:GPO)) RETURN p
```


### Find all Certificate Templates

 ```text
MATCH (n:GPO) WHERE n.type = 'Certificate Template' RETURN n
```


### Find enabled Certificate Templates

 ```text
MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.Enabled = true RETURN n
```


### Find Certificate Authorities

 ```text
MATCH (n:GPO) WHERE n.type = 'Enrollment Service' RETURN n
```


### Show Enrollment Rights for Certificate Template

 ```text
MATCH (n:GPO) WHERE n.type = 'Certificate Template' RETURN n.name
```


### Show Enrollment Rights for Certificate Template

 ```text
MATCH p=(g)-[:Enroll|AutoEnroll]->(n:GPO {name:$result}) WHERE n.type = 'Certificate Template' return p
```


### Show Rights for Certificate Authority

 ```text
MATCH (n:GPO) WHERE n.type = 'Enrollment Service' RETURN n.name
```


### Show Rights for Certificate Authority

 ```text
MATCH p=(g)-[:ManageCa|ManageCertificates|Auditor|Operator|Read|Enroll]->(n:GPO {name:$result}) return p
```


### Find Misconfigured Certificate Templates (ESC1)

 ```text
MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.`Enrollee Supplies Subject` = true and n.`Client Authentication` = true and n.`Enabled` = true  RETURN n
```


### Shortest Paths to Misconfigured Certificate Templates from Owned Principals (ESC1)

 ```text
MATCH p=allShortestPaths((g {owned:true})-[*1..]->(n:GPO)) WHERE  g<>n and n.type = 'Certificate Template' and n.`Enrollee Supplies Subject` = true and n.`Client Authentication` = true and n.`Enabled` = true return p
```


### Find Misconfigured Certificate Templates (ESC2)

 ```text
MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.`Enabled` = true and (n.`Extended Key Usage` = [] or 'Any Purpose' IN n.`Extended Key Usage`)  RETURN n
```


### Shortest Paths to Misconfigured Certificate Templates from Owned Principals (ESC2)

 ```text
MATCH p=allShortestPaths((g {owned:true})-[*1..]->(n:GPO)) WHERE  g<>n and n.type = 'Certificate Template' and n.`Enabled` = true and (n.`Extended Key Usage` = [] or 'Any Purpose' IN n.`Extended Key Usage`) return p
```


### Find Enrollment Agent Templates (ESC3)

 ```text
MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.`Enabled` = true and (n.`Extended Key Usage` = [] or 'Any Purpose' IN n.`Extended Key Usage` or 'Certificate Request Agent' IN n.`Extended Key Usage`)  RETURN n
```


### Shortest Paths to Enrollment Agent Templates from Owned Principals (ESC3)

 ```text
MATCH p=allShortestPaths((g {owned:true})-[*1..]->(n:GPO)) WHERE  g<>n and n.type = 'Certificate Template' and n.`Enabled` = true and (n.`Extended Key Usage` = [] or 'Any Purpose' IN n.`Extended Key Usage` or 'Certificate Request Agent' IN n.`Extended Key Usage`) return p
```


### Shortest Paths to Vulnerable Certificate Template Access Control (ESC4)

 ```text
MATCH p=shortestPath((g)-[:GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner*1..]->(n:GPO)) WHERE  g<>n and n.type = 'Certificate Template' and n.`Enabled` = true RETURN p
```


### Shortest Paths to Vulnerable Certificate Template Access Control from Owned Principals (ESC4)

 ```text
MATCH p=allShortestPaths((g {owned:true})-[r*1..]->(n:GPO)) WHERE g<>n and n.type = 'Certificate Template' and n.Enabled = true and NONE(x in relationships(p) WHERE type(x) = 'Enroll' or type(x) = 'AutoEnroll') return p
```


### Find Certificate Authorities with User Specified SAN (ESC6)

 ```text
MATCH (n:GPO) WHERE n.type = 'Enrollment Service' and n.`User Specified SAN` = 'Enabled' RETURN n
```


### Shortest Paths to Vulnerable Certificate Authority Access Control (ESC7)

 ```text
MATCH p=shortestPath((g)-[r:GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|ManageCa|ManageCertificates*1..]->(n:GPO)) WHERE  g<>n and n.type = 'Enrollment Service' RETURN p
```


### Shortest Paths to Vulnerable Certificate Authority Access Control from Owned Principals (ESC7)

 ```text
MATCH p=allShortestPaths((g {owned:true})-[*1..]->(n:GPO)) WHERE  g<>n and n.type = 'Enrollment Service' and NONE(x in relationships(p) WHERE type(x) = 'Enroll' or type(x) = 'AutoEnroll') RETURN p
```


### Find Certificate Authorities with HTTP Web Enrollment (ESC8)

 ```text
MATCH (n:GPO) WHERE n.type = 'Enrollment Service' and n.`Web Enrollment` = 'Enabled' RETURN n
```


### Find Unsecured Certificate Templates (ESC9)

 ```text
MATCH (n:GPO) WHERE n.type = 'Certificate Template' and n.`Enrollee Supplies Subject` = true and n.`Client Authentication` = true and n.`Enabled` = true  RETURN n
```


### Find Unsecured Certificate Templates (ESC9)

 ```text
MATCH (n:GPO) WHERE n.type = 'Certificate Template' and 'NoSecurityExtension' in n.`Enrollment Flag` and n.`Enabled` = true  RETURN n
```


### Shortest Paths to Unsecured Certificate Templates from Owned Principals (ESC9)

 ```text
MATCH p=allShortestPaths((g {owned:true})-[r*1..]->(n:GPO)) WHERE n.type = 'Certificate Template' and g<>n and 'NoSecurityExtension' in n.`Enrollment Flag` and n.`Enabled` = true and NONE(rel in r WHERE type(rel) in ['EnabledBy','Read','ManageCa','ManageCertificates']) return p
```


### List all owned users

 ```text
MATCH (m:User) WHERE m.owned=TRUE RETURN m
```


### List all owned groups

 ```text
MATCH (m:Group) WHERE m.owned=TRUE RETURN m
```


### List all High Valued Owned Targets

 ```text
MATCH (m) WHERE m.highvalue=TRUE AND m.owned = true RETURN m
```


### List the groups of all owned users

 ```text
MATCH (m:User) WHERE m.owned=TRUE WITH m MATCH p=(m)-[:MemberOf*1..]->(n:Group) RETURN p
```


### Find the Shortest path to a high value target from an owned object

 ```text
MATCH p=shortestPath((g {owned:true})-[*1..]->(n {highvalue:true})) WHERE  g<>n return p
```


### Find Kerberoastable Users with a path to DA

 ```text
MATCH (u:User {hasspn:true}) MATCH (g:Group) WHERE g.objectid ENDS WITH '-512' MATCH p = shortestPath( (u)-[*1..]->(g) ) RETURN p
```


### Find objects with SPN and either allowedtodelegate, admincount or unconstrained delegation

 ```text
MATCH (c {hasspn: True}) WHERE c.allowedtodeledate=true OR c.unconstraineddelegation=true OR c.admincount RETURN c
```


### Find ASREPRoastable Users with a path to DA

 ```text
MATCH (u:User {dontreqpreauth: true}) MATCH (g:Group) WHERE g.objectid ENDS WITH '-512' MATCH p = shortestPath( (u)-[*1..]->(g) ) RETURN p
```


### Find the Shortest path to a unconstrained delegation system from an owned object

 ```text
MATCH (n) MATCH p=shortestPath((n)-[*1..]->(m:Computer {unconstraineddelegation: true})) WHERE NOT n=m AND n.owned = true RETURN p
```


### Find machines Domain Users can RDP into

 ```text
match p=(g:Group)-[:CanRDP]->(c:Computer) where g.objectid ENDS WITH '-513' return p
```


### Find what groups can RDP

 ```text
MATCH p=(m:Group)-[r:CanRDP]->(n:Computer) RETURN p
```


### Find if any domain user has interesting permissions against a GPO (Warning: Heavy)

 ```text
MATCH p=(u:User)-[r:AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|GpLink*1..]->(g:GPO) RETURN p
```


### Find groups that can reset passwords (Warning: Heavy)

 ```text
MATCH p=(m:Group)-[r:ForceChangePassword]->(n:User) RETURN p
```


### Top 100 with most Outbound Controlled Object

 ```text
MATCH p=(u)-[r1]->(n) WHERE r1.isacl=true WITH u as u, COUNT(DISTINCT(n)) as controlled WHERE u.name IS NOT NULL  RETURN u LIMIT 100
```


### Find computer account with a SPN containing MSSQL

 ```text
MATCH (c:Computer) WHERE ANY (x IN c.serviceprincipalnames WHERE toUpper(x) CONTAINS 'MSSQL') RETURN c
```


### Find accounts that are MSSQL Admins on computers

 ```text
MATCH p=(u:User)-[r:SQLAdmin]->(c:Compiter) RETURN p
```


### Find groups with adminCount=True but not in High Value target

 ```text
MATCH p = (g:Group {admincount: True}) WHERE NOT EXISTS(g.highvalue) OR g.highvalue = False RETURN g
```


### Find groups that have local admin rights but admincount=0

 ```text
MATCH p=(n:Group)-[:AdminTo*1..]->(m:Computer) WHERE NOT n.admincount RETURN p
```


### Find groups that have local admin rights (Warning: Heavy)

 ```text
MATCH p=(m:Group)-[r:AdminTo]->(n:Computer) RETURN p
```


### Find all users that have directly local admin rights

 ```text
MATCH p=(m:User)-[r:AdminTo]->(n:Computer) RETURN p
```


### Find all users that have directly or indrectly local admin rights (Warning: Heavy)

 ```text
MATCH p = (u:User)-[r:AdminTo|MemberOf*1..]->(c:Computer) RETURN p
```


### Find all computers that have local admin rights

 ```text
MATCH p=(m:Computer)-[r:AdminTo]->(n:Computer) RETURN p
```


### Find all active Domain Admin sessions

 ```text
MATCH (n:User)-[:MemberOf]->(g:Group) WHERE g.objectid ENDS WITH '-512' MATCH p = (c:Computer)-[:HasSession]->(n) return p
```


### Find all computers with Unconstrained Delegation

 ```text
MATCH (c:Computer {unconstraineddelegation:true}) return c
```


### Find all computers with unsupported operating systems

 ```text
MATCH (H:Computer) WHERE H.operatingsystem = '.*(2000|2003|2008|xp|vista|7|me).*' RETURN H
```


### Find users that logged in within the last 90 days

 ```text
MATCH (u:User) WHERE u.lastlogon < (datetime().epochseconds - (90 * 86400)) and NOT u.lastlogon IN [-1.0, 0.0] RETURN u
```


### Find users with passwords last set within the last 90 days

 ```text
MATCH (u:User) WHERE u.pwdlastset < (datetime().epochseconds - (90 * 86400)) and NOT u.pwdlastset IN [-1.0, 0.0] RETURN u
```


### All Users with Password not Required

 ```text
MATCH p = (d:Domain)-[r:Contains*1..]->(u:User) WHERE u.passwordnotreqd = true RETURN p
```


### Find users that have not logged in within the last 90 days

 ```text
MATCH (u:User) WHERE u.lastlogon > (datetime().epochseconds - (90 * 86400)) and NOT u.lastlogon IN [-1.0, 0.0] RETURN u
```


### Find users with passwords last set over 90 days

 ```text
MATCH (u:User) WHERE u.pwdlastset > (datetime().epochseconds - (90 * 86400)) and NOT u.pwdlastset IN [-1.0, 0.0] RETURN u
```


### Find constrained delegation

 ```text
MATCH p=(u:User)-[:AllowedToDelegate]->(c:Computer) RETURN p
```


### Find computers that allow unconstrained delegation that AREN’T domain controllers.

 ```text
MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' WITH COLLECT(c1.name) AS domainControllers MATCH (c2:Computer {unconstraineddelegation:true}) WHERE NOT c2.name IN domainControllers RETURN c2
```


### View all GPOs

 ```text
Match (n:GPO) RETURN n
```


### View all groups that contain the word 'admin'

 ```text
Match (n:Group) WHERE n.name CONTAINS 'ADMIN' RETURN n
```


### Find users with PasswordNeverExpires

 ```text
MATCH (u:User {pwdneverexpires: True}) WHERE NOT u.name starts with 'KRBTGT' RETURN u
```


### Find nodes with juicy keyword in name or description

 ```text
UNWIND ["admin", "amministratore", "contrase", "empfidlich", "geheim", "hasło", "important", "azure", "MSOL", "Kennwort", "parol", "parola", "pass", "passe", "secret", "secreto", "segreto", "sekret", "sensibil", "sensibile", "sensible", "sensitive", "wrażliw"] AS word MATCH (n) WHERE (toLower(n.name) CONTAINS toLower(word)) OR (toLower(n.description) CONTAINS toLower(word)) RETURN n
```


### Find nodes that contain UNC paths to SMB share in description

 ```text
MATCH (n) WHERE n.description CONTAINS '\\' RETURN n
```


### Find all other rights Domain Users should not have

 ```text
MATCH p=(m:Group)-[r:Owns|WriteDacl|GenericAll|WriteOwner|ExecuteDCOM|GenericWrite|AllowedToDelegate|ForceChangePassword]->(n:Computer) WHERE m.name STARTS WITH 'DOMAIN USERS' RETURN p
```


### Find user without adminCount that have interesting ACL

 ```text
MATCH p=(u:User)-[r:Owns|WriteDacl|GenericAll|WriteOwner|ExecuteDCOM|GenericWrite|AllowedToDelegate|ForceChangePassword]->(n:Computer) WHERE u.admincount=false RETURN p
```


### Find computer without adminCount that have interesting ACL

 ```text
MATCH p=(c:Computer)-[r:Owns|WriteDacl|GenericAll|WriteOwner|ExecuteDCOM|GenericWrite|AllowedToDelegate|ForceChangePassword]->(n:Computer) WHERE c.admincount=false RETURN p
```


### Show all high value target's groups

 ```text
MATCH p=(n:User)-[r:MemberOf*1..]->(m:Group {highvalue:true}) RETURN p
```


### Find computers with constrained delegation permissions and the corresponding targets where they allowed to delegate

 ```text
MATCH (c:Computer) WHERE c.allowedtodelegate IS NOT NULL RETURN c
```


### Find if any domain user has interesting permissions against a GPO (Warning: Heavy)

 ```text
MATCH p=(u:User)-[r:AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|GpLink*1..]->(g:GPO) RETURN p
```


### Find if unprivileged users have rights to add members into groups

 ```text
MATCH (n:User {admincount:False}) MATCH p=allShortestPaths((n)-[r:AddMember*1..]->(m:Group)) RETURN p
```


### Find users that have never logged on and account is still active

 ```text
MATCH (n:User) WHERE n.lastlogontimestamp=-1.0 AND n.enabled=TRUE RETURN n
```


### Find an object from domain 'A' that can do anything to a foreign object

 ```text
MATCH (n:Domain) RETURN n.name ORDER BY n.name
```


### Find an object from domain 'A' that can do anything to a foreign object

 ```text
MATCH p=(n {domain:$result})-[r]->(d) WHERE NOT d.domain=n.domain RETURN p
```


### Find All edges any owned user has on a computer

 ```text
MATCH p=shortestPath((m:User)-[r*]->(b:Computer)) WHERE m.owned RETURN p
```


### Find Server 2000

 ```text
MATCH (H:Computer) WHERE H.operatingsystem =~ '(?i).*(2000).*' RETURN H
```


### Find Server 2000 with session

 ```text
MATCH (H:Computer)-[:HasSession]->(y) WHERE H.operatingsystem =~ '(?i).*(2000).*' RETURN H
```


### Find Server 2003

 ```text
MATCH (H:Computer) WHERE H.operatingsystem =~ '(?i).*(2003).*' RETURN H
```


### Find Server 2008 with session

 ```text
MATCH (H:Computer)-[:HasSession]->(y) WHERE H.operatingsystem =~ '(?i).*(2008).*' RETURN H
```


### Find Windows XP

 ```text
MATCH (H:Computer) WHERE H.operatingsystem =~ '(?i).*(xp).*' RETURN H
```


### Find Windows XP with session

 ```text
MATCH (H:Computer)-[:HasSession]->(y) WHERE H.operatingsystem =~ '(?i).*(xp).*' RETURN H
```


### Find Windows 7

 ```text
MATCH (H:Computer) WHERE H.operatingsystem =~ '(?i).*(7).*' RETURN H
```


### Find Windows 7 session

 ```text
MATCH (H:Computer)-[:HasSession]->(y) WHERE H.operatingsystem =~ '(?i).*(7).*' RETURN H
```


### Find Server 2012

 ```text
MATCH (H:Computer) WHERE H.operatingsystem =~ '(?i).*(2012).*' RETURN H
```


### Find Server 2012 with session

 ```text
MATCH (H:Computer)-[:HasSession]->(y) WHERE H.operatingsystem =~ '(?i).*(2012).*' RETURN H
```


### Find Server 2016

 ```text
MATCH (H:Computer) WHERE H.operatingsystem =~ '(?i).*(2016).*' RETURN H
```


### Find Server 2016 with session

 ```text
MATCH (H:Computer)-[:HasSession]->(y) WHERE H.operatingsystem =~ '(?i).*(2016).*' RETURN H
```


### Find Server 2019

 ```text
MATCH (H:Computer) WHERE H.operatingsystem =~ '(?i).*(2019).*' RETURN H
```


### Find Server 2019 with session

 ```text
MATCH (H:Computer)-[:HasSession]->(y) WHERE H.operatingsystem =~ '(?i).*(2019).*' RETURN H
```


### Set DCSync Principals as High Value Targets

 ```text
MATCH (s)-[r:MemberOf|GetChanges*1..]->(d:Domain) WITH s, d MATCH (s)-[r:MemberOf|GetChangesAll*1..]->(d) WITH s, d MATCH p = (s)-[r:MemberOf|GetChanges|GetChangesAll*1..]->(d) WHERE s.highvalue = false SET s.highvalue = true, s.highvaluereason = 'DCSync Principal' RETURN s
```


### Set Unconstrained Delegation Principals as High Value Targets

 ```text
MATCH p = (d:Domain)-[r:Contains*1..]->(uc) WHERE (uc:User OR uc:Computer) AND uc.unconstraineddelegation = true AND uc.highvalue = false SET uc.highvalue = true, uc.highvaluereason = 'Unconstrained Delegation Principal' RETURN p
```


### Set Local Admin or Reset Password Principals as High Value Targets

 ```text
MATCH (a)-[r:AdminTo|ForceChangePassword]->(b) WHERE a.highvalue = false SET a.highvalue = true, a.highvaluereason = 'Local Admin or Reset Password Principal' RETURN a
```


### Set Principals with Privileges on Computers as High Value Targets

 ```text
MATCH (a)-[r:AllowedToDelegate|ExecuteDCOM|ForceChangePassword|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner]->(n:Computer) WHERE a.highvalue = false SET a.highvalue = true, a.highvaluereason = 'Principal with Privileges on Computers' RETURN a
```


### Set Principals with Privileges on Cert Publishers as High Value Targets

 ```text
MATCH (a)-[r:GenericAll|GenericWrite|MemberOf|Owns|WriteDacl|WriteOwner]->(g:Group) WHERE g.objectid =~ 'S-1-5-21-.*-517' AND a.highvalue = false SET a.highvalue = true, a.highvaluereason = 'Principal with Privileges on the Cert Publisher group' RETURN a
```


### Set Principals with Privileges on High Value Targets as High Value Targets

 ```text
MATCH (a)-[r:GenericAll|GenericWrite|MemberOf|Owns|WriteDacl|WriteOwner]->(b) WHERE b.highvalue=true AND a.highvalue = false SET a.highvalue = true, a.highvaluereason = 'Principal with Privileges on the Cert Publisher group' RETURN a
```


### Set Members of High Value Targets Groups as High Value Targets

 ```text
MATCH (a)-[r:MemberOf*1..]->(g:Group) WHERE a.highvalue = false AND g.highvalue = true SET a.highvalue = true, a.highvaluereason = 'Member of High Value Target Group' RETURN a
```


### Remove Inactive Users and Computers from High Value Targets

 ```text
MATCH (uc) WHERE uc.highvalue = true AND ((uc:User AND uc.enabled = false) OR (uc:Computer AND ((uc.enabled = false) OR (uc.lastlogon > 0 AND uc.lastlogon < (TIMESTAMP() / 1000 - 15552000)) OR (uc.lastlogontimestamp > 0 AND uc.lastlogontimestamp < (TIMESTAMP() / 1000 - 15552000))))) SET uc.highvalue = false, uc.nothighvaluereason = 'Inactive' RETURN uc
```