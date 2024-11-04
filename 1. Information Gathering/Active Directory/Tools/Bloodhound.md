[[Index.canvas|Index]]

## Setup

```
sudo neo4j start
```

neo4j:neo4j
neo4j:bloodhound

## Remote Bloodhound
```
bloodhound-python -u fsmith -p Thestrokes23 -d egotistical-bank.local -dc sauna.egotistical-bank.local -ns 10.10.10.175 -c All
```

## Bloodhound Queries
SQL Admin query
```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

Remote Management Users query
```
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

