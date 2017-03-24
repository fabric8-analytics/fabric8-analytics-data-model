import json
all_data = json.loads(open("data/npm--serve-static-1.7.1").read())
print(all_data["package"])
print(all_data["version"])
print(all_data["ecosystem"])
