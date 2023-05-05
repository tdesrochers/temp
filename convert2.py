import json

# Load the osquery schema JSON file
with open("osquery_schema.json", "r") as f:
    osquery_schema = json.load(f)

# Define the Elastic Common Schema
ecs = {
    "event": {
        "created": "event.created",
        "kind": "event.kind",
        "category": "event.category",
        "type": "event.type",
        "id": "event.id",
        "module": "event.module"
    },
    "host": {
        "name": "host.name",
        "hostname": "host.hostname",
        "id": "host.id",
        "ip": "host.ip"
    },
    "user": {
        "id": "user.id",
        "name": "user.name"
    },
    "process": {
        "pid": "process.pid",
        "name": "process.name",
        "args": "process.args"
    },
    "file": {
        "path": "file.path",
        "name": "file.name",
        "inode": "file.inode",
        "uid": "file.uid",
        "gid": "file.gid",
        "owner": "file.owner",
        "group": "file.group",
        "mode": "file.mode",
        "size": "file.size",
        "mtime": "file.mtime",
        "ctime": "file.ctime",
        "atime": "file.atime"
    },
    "network": {
        "direction": "network.direction",
        "protocol": "network.protocol",
        "transport": "network.transport",
        "src": "network.src",
        "src_port": "network.src_port",
        "dst": "network.dst",
        "dst_port": "network.dst_port"
    }
}

# Define a function to convert an osquery column name to an ECS field name
def convert_column_to_field(column_name):
    parts = column_name.split(".")
    if len(parts) == 2:
        table_name, column_name = parts
        if table_name in ecs and column_name in ecs[table_name]:
            return ecs[table_name][column_name]
    return column_name

# Convert the osquery schema to the Elastic Common Schema
ecs_schema = {}
for table_name, columns in osquery_schema.items():
    ecs_schema[table_name] = {}
    for column_name, column_type in columns.items():
        ecs_field_name = convert_column_to_field(column_name)
        ecs_schema[table_name][ecs_field_name] = column_type

# Save the Elastic Common Schema to a JSON file
with open("ecs_schema.json", "w") as f:
    json.dump(ecs_schema, f, indent=4)