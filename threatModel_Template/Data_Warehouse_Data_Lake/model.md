# Threat Model: Data Warehouse / Data Lake Architecture

## Description
Data warehouse and data lake architecture with ETL pipelines, object storage, data lakehouse, and BI tools.

## Context
gdaf_context = context/datawarehouse_context.yaml
bom_directory = BOM

## Boundaries
- **Data Sources**: isTrusted=False, color=red
- **Ingestion Layer**: isTrusted=True, color=orange
- **Storage Layer (Raw/Curated)**: isTrusted=True, color=lightblue
- **Processing Layer**: isTrusted=True, color=green
- **Consumption Layer**: isTrusted=False, color=purple

## Actors
- **Data Provider**: boundary="Data Sources"
- **Data Engineer**: boundary="Ingestion Layer"
- **Data Analyst**: boundary="Consumption Layer"
- **Business User**: boundary="Consumption Layer"

## Servers
- **ETLPipeline**: boundary="Ingestion Layer", type="etl_tools"
- **ObjectStorage**: boundary="Storage Layer (Raw/Curated)", type="object_storage"
- **DataLakehouse**: boundary="Storage Layer (Raw/Curated)", type="data_lakehouse"
- **SparkCluster**: boundary="Processing Layer", type="compute_cluster"
- **DataWarehouse**: boundary="Processing Layer", type="data_warehouse"
- **BITools**: boundary="Consumption Layer", type="bi_tools"

## Dataflows
- **Data Ingestion**: from="Data Provider", to="ETLPipeline", protocol="Various (API, SFTP, Streaming)"
- **Load to Raw Storage**: from="ETLPipeline", to="ObjectStorage", protocol="Internal API"
- **Data Transformation**: from="ObjectStorage", to="SparkCluster", protocol="Internal API"
- **Load to Curated**: from="SparkCluster", to="DataLakehouse", protocol="Internal API"
- **Query Data**: from="BITools", to="DataWarehouse", protocol="JDBC/ODBC"
- **Access Raw Data**: from="Data Analyst", to="ObjectStorage", protocol="API"
- **Access Curated Data**: from="Business User", to="DataLakehouse", protocol="API"

## Protocol Styles
- **Various (API, SFTP, Streaming)**: color=blue, line_style=dashed
- **Internal API**: color=gray, line_style=dashed
- **JDBC/ODBC**: color=purple, line_style=dashed
- **API**: color=darkgreen, line_style=solid

## Severity Multipliers
- **DataWarehouse**: 2.0
- **DataLakehouse**: 2.0
- **ObjectStorage**: 1.8
- **SparkCluster**: 1.5
