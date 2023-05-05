import json

osquery_schema = json.load(open('osquery.schema'))

es_schema = {
    'mappings': {} 
}

for table_name, columns in osquery_schema.items():
    es_schema['mappings'][table_name] = {
        'properties': {}
    }
    for column_name, column in columns.items():
        data_type = column_type_mapping[column['type']]
        es_schema['mappings'][table_name]['properties'][column_name] = {
            'type': data_type 
        }

json.dump(es_schema, open('es_schema.json','w'))

This uses a simple mapping between OSQuery column types to Elasticsearch data types:
column_type_mapping = {
    'TEXT': 'text', 
    'INTEGER': 'long', 
    'BIGINT': 'long', 
    'REAL': 'double', 
    'INTEGER UNSIGNED': 'long', 
    'BIGINT UNSIGNED': 'long' 
}

So if your osquery.schema is:
{
  "osquery_info": {
    "name": "TEXT", 
    "version": "TEXT", 
    "timezone": "TEXT", 
    "user": "TEXT" 
  }, 
  "osquery_results": {
    "time": "BIGINT", 
    "tablename": "TEXT", 
    "name": "TEXT", 
    "value": "TEXT" 
  } 
} 

You'll get an es_schema.json like this:
{ 
  "mappings": { 
    "osquery_info": { 
      "properties": { 
        "name":  { 
          "type":  "text" 
        }, 
        "version":  { 
          "type":  "text" 
        }, 
        "timezone":  { 
          "type":  "text" 
        }, 
        "user":  { 
          "type":  "text" 
        } 
      } 
    }, 
    "osquery_results": { 
      "properties": { 
        "time":  { 
          "type":  "long" 
        }, 
        "tablename":  { 
          "type":  "text" 
        }, 
        "name":  { 
          "type":  "text" 
        }, 
        "value":  { 
          "type":  "text" 
        } 
      } 
    } 
  } 
}