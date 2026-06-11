import json

DEPARTMENT = "department.json"

def load_dep():
    with open(DEPARTMENT, "r") as f:
        return json.load(f)

def if_dep_exist(name):
    data = load_dep()
    check = False
    for department in data["departments"]:
        if department["name"] == name:
            check = True
            break
    return check


data = load_dep()

print(if_dep_exist("B2"))
