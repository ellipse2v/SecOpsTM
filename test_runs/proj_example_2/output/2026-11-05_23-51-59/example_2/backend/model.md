## Servers
- **APIGateway**: type="api_gateway", entry_point=True
- **AuthService**:
- **OrderService**:
- **ProductDB**: submodel=./database/model.md, type="database"

## Dataflows
- **GatewayToAuth**: from=APIGateway, to=AuthService, protocol=gRPC
- **GatewayToOrders**: from=APIGateway, to=OrderService, protocol=gRPC
- **OrdersToDB**: from=OrderService, to=ProductDB, protocol=TCP

## Protocol Styles
- **gRPC**: color=blue, line_style=dashed
- **TCP**: color=black, line_style=dotted
