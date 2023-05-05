import json

# Load the osquery schema
with open('osquery_schema.json', 'r') as f:
    osquery_schema = json.load(f)

# Load the ECS schema
with open('ecs_schema.json', 'r') as f:
    ecs_schema = json.load(f)

# Create a dictionary to store the field mappings
field_mappings = {}

# Iterate over the osquery schema fields
for field_name, field_info in osquery_schema.items():
    # Check if the field has a mapping in the ECS schema
    if field_name in ecs_schema['properties']:
        # Get the ECS field name and description
        ecs_field_name = field_name.replace('.', '_')
        ecs_field_desc = ecs_schema['properties'][field_name]['description']

        # Add the field mapping to the dictionary
        field_mappings[field_name] = {'ecs_field_name': ecs_field_name, 'ecs_field_desc': ecs_field_desc}

# Print the field mappings as a table
print('{:<40} {:<40} {}'.format('Osquery Field Name', 'ECS Field Name', 'Description'))
print('{:<40} {:<40} {}'.format('-'*40, '-'*40, '-'*40))
for osquery_field, mapping in field_mappings.items():
    print('{:<40} {:<40} {}'.format(osquery_field, mapping['ecs_field_name'], mapping['ecs_field_desc']))