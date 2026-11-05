## Context
gdaf_context = context/example2_context.yaml
bom_directory = BOM

## Actors
- **User**:

## Servers
- **WebApp**: submodel=./frontend/model.md
- **BackendServices**: submodel=./backend/model.md

## Data
- **User Request**:
- **API Call**:

## Dataflows
- **UserToWebApp**: from=User, to=WebApp, protocol=HTTPS, data="User Request"
- **WebAppToBackend**: from=WebApp, to=BackendServices, protocol=HTTP, data="API Call"
