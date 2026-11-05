## Boundaries
- **Internet**: type=External, isTrusted=false
- **DMZ**: type=Internal, isTrusted=true
- **Internal Network**: type=Internal, isTrusted=true

## Actors
- **External User**: isHuman=true, boundary=Internet

## Servers
- **WebServer_1**: stereotype=Server, boundary=DMZ, services=['web']
- **AppServer_1**: stereotype=Server, boundary=Internal Network, services=['app']
- **DBServer_1**: stereotype=Server, boundary=Internal Network, services=['db']

## Data
- **Web Traffic**: classification=PUBLIC, lifetime=TRANSIENT
- **Application Requests**: classification=RESTRICTED, lifetime=TRANSIENT
- **Database Queries**: classification=RESTRICTED, lifetime=TRANSIENT

## Dataflows
- **User to WebServer**: from="External User", to="WebServer_1", protocol="HTTPS", data="Web Traffic", description="External user accesses web server"
- **WebServer to AppServer**: from="WebServer_1", to="AppServer_1", protocol="HTTP/S", data="Application Requests", description="Web server communicates with application server"
- **AppServer to DBServer**: from="AppServer_1", to="DBServer_1", protocol="DB", data="Database Queries", description="Application server communicates with database server"
