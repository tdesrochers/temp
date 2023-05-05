Sure! Here's an example Python script that takes an osquery results file as input, converts the fields to ECS format, and outputs the results to a new file:

```python
import json

# Define a function to convert the osquery fields to ECS format
def convert_to_ecs(osquery_result):
    ecs_result = {}
    ecs_result["event"] = {}
    ecs_result["process"] = {}
    ecs_result["file"] = {}
    ecs_result["network"] = {}
    ecs_result["host"] = {}

    # Map the osquery fields to ECS fields
    if "action" in osquery_result:
        ecs_result["event"]["action"] = osquery_result["action"]
    if "created_at" in osquery_result:
        ecs_result["event"]["created"] = osquery_result["created_at"]
    if "device" in osquery_result:
        ecs_result["event"]["dataset"] = osquery_result["device"]
    if "cmdline" in osquery_result:
        ecs_result["process"]["command_line"] = osquery_result["cmdline"]
    if "cpu_time" in osquery_result:
        ecs_result["process"]["cpu"] = {"total": {"pct": osquery_result["cpu_time"]}}
    if "directory_path" in osquery_result:
        ecs_result["file"]["directory"] = {"path": osquery_result["directory_path"]}
    if "dst_port" in osquery_result:
        ecs_result["network"]["destination"] = {"port": osquery_result["dst_port"]}
    if "dst_ip" in osquery_result:
        ecs_result["network"]["destination"] = {"ip": osquery_result["dst_ip"]}
    if "exe" in osquery_result:
        ecs_result["process"]["executable"] = {"path": osquery_result["exe"]}
    if "file_path" in osquery_result:
        ecs_result["file"]["path"] = osquery_result["file_path"]
    if "gid" in osquery_result:
        ecs_result["process"]["entity_id"] = {"group": {"id": osquery_result["gid"]}}
    if "groupname" in osquery_result:
        ecs_result["process"]["entity_id"] = {"group": {"name": osquery_result["groupname"]}}
    if "hash" in osquery_result:
        ecs_result["file"]["hash"] = {"sha256": osquery_result["hash"]}
    if "hostname" in osquery_result:
        ecs_result["host"]["name"] = osquery_result["hostname"]
    if "id" in osquery_result:
        ecs_result["process"]["pid"] = osquery_result["id"]
    if "interface" in osquery_result:
        ecs_result["network"]["interface"] = {"name": osquery_result["interface"]}
    if "md5" in osquery_result:
        ecs_result["file"]["hash"] = {"md5": osquery_result["md5"]}
    if "name" in osquery_result:
        ecs_result["process"]["name"] = osquery_result["name"]
    if "path" in osquery_result:
        ecs_result["process"]["executable"] = {"path": osquery_result["path"]}
    if "pid" in osquery_result:
        ecs_result["process"]["pid"] = osquery_result["pid"]
    if "ppid" in osquery_result:
        ecs_result["process"]["parent"] = {"pid": osquery_result["ppid"]}
    if "protocol" in osquery_result:
        ecs_result["network"]["protocol"] = osquery_result["protocol"]
    if "real_uid" in osquery_result:
        ecs_result["process"]["entity_id"] = {"user": {"real": {"id": osquery_result["real_uid"]}}}
    if "real_username" in osquery_result:
        ecs_result["process"]["entity_id"] = {"user": {"real": {"name": osquery_result["real_username"]}}}
    if "sha1" in osquery_result:
        ecs_result["file"]["hash"] = {"sha1": osquery_result["sha1"]}
    if "sha256" in osquery_result:
        ecs_result["file"]["hash"] = {"sha256": osquery_result["sha256"]}
    if "size" in osquery_result:
        ecs_result["file"]["size"] = osquery_result["size"]
    if "src_port" in osquery_result:
        ecs_result["network"]["source"] = {"port": osquery_result["src_port"]}
    if "src_ip" in osquery_result:
        ecs_result["network"]["source"] = {"ip": osquery_result["src_ip"]}
    if "start_time" in osquery_result:
        ecs_result["process"]["start_time"] = osquery_result["start_time"]
    if "status" in osquery_result:
        ecs_result["process"]["status"] = osquery_result["status"]
    if "target_path" in osquery_result:
        ecs_result["file"]["target_path"] = osquery_result["target_path"]
    if "target_permissions" in osquery_result:
        ecs_result["file"]["target"] = {"permissions": osquery_result["target_permissions"]}
    if "target_uid" in osquery_result:
        ecs_result["file"]["target"]["entity_id"] = {"user": {"id": osquery_result["target_uid"]}}
    if "target_username" in osquery_result:
        ecs_result["file"]["target"]["entity_id"] = {"user": {"name": osquery_result["target_username"]}}
    if "time" in osquery_result:
        ecs_result["event"]["created"] = osquery_result["time"]
    if "uid" in osquery_result:
        ecs_result["process"]["entity_id"] = {"user": {"id": osquery_result["uid"]}}
    if "username" in osquery_result:
        ecs_result["process"]["entity_id"] = {"user": {"name": osquery_result["username"]}}
    if "version" in osquery_result:
        ecs_result["osquery"] = {"version": osquery_result["version"]}

    return ecs_result

# Open the osquery results file
with open("osquery_results.json", "r") as f:
    osquery_results = json.load(f)

# Convert each result to ECS format and append to a list
ecs_results = []
for osquery_result in osquery_results:
    ecs_result = convert_to_ecs(osquery_result)
    ecs_results.append(ecs_result)

# Write the ECS results to a new file
with open("ecs_results.json", "w") as f:
    json.dump(ecs_results, f, indent=2)
```

This script assumes that the osquery results file is in JSON format and has the same structure as the output of the `osqueryi` command. If your results file is in a different format, you may need to modify the script accordingly.