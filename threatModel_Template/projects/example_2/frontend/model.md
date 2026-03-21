## Servers
- **WebServer**: type="web_server"
- **LoadBalancer**: type="load_balancer", entry_point=True

## Dataflows
- **EntryToLB**: from=WebServer, to=LoadBalancer, protocol=HTTPS
- **LBtoWeb**: from=LoadBalancer, to=WebServer, protocol=HTTP

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=solid
