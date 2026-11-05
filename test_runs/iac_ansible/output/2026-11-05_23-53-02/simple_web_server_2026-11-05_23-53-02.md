## Boundaries
- **Internet**: type=External, isTrusted=false
- **DMZ**: type=Internal, isTrusted=true, servers=['WebServer']

## Actors
- **External User**: isHuman=true, boundary=Internet

## Servers
- **WebServer**: stereotype=Server, boundary=DMZ, services=['web']

## Data
- **Web Traffic**: classification=PUBLIC, lifetime=TRANSIENT

## Dataflows
- **User to WebServer HTTP**: from="External User", to="WebServer", protocol="HTTP", data="Web Traffic", description="External user accesses web server over HTTP"
- **User to WebServer HTTPS**: from="External User", to="WebServer", protocol="HTTPS", data="Web Traffic", description="External user accesses web server over HTTPS"
