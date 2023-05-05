import json 

osquery_schema = json.load(open('osquery.schema'))  

es_schema = {  
    'mappings': {}  
}  

for table_name, columns in osquery_schema.items():  
    if isinstance(columns, list): 
        es_schema['mappings'][table_name] = {  
            'properties': {}  
        }  
        for col in columns: 
            column_name, column = list(col.items())[0] 
            data_type = column_type_mapping[column['type']] 
            es_schema['mappings'][table_name]['properties'][column_name] = {  
                'type': data_type  
            }  
    else: 
        es_schema['mappings'][table_name] = {  
            'properties': {}  
        }  
        for column_name, column in columns.items(): 
            data_type = column_type_mapping[column['type']] 
            es_schema['mappings'][table_name]['properties'][column_name] = {  
                'type': data_type  
            }  

json.dump(es_schema, open('es_schema.json','w')) 
