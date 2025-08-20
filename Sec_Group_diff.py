import requests
import yaml
import os

NSX_MANAGER = "https://<NSX_MANAGER>"
USERNAME = "<USERNAME>"
PASSWORD = "<PASSWORD>"
SEC_GROUPS_FILE = "nsxt_ipset_dyn_groups.yaml"
UPDATES_FILE = "nsxt_ipset_dyn_group_updates.yaml"
VERIFY_SSL = False  # Set to True if using valid SSL cert

def get_sec_groups():
    url = f"{NSX_MANAGER}/policy/api/v1/infra/domains/default/groups"
    session = requests.Session()
    session.auth = (USERNAME, PASSWORD)
    session.verify = VERIFY_SSL
    params = {"page_size": 1000}
    ipset_dyn_groups = []

    while True:
        response = session.get(url, params=params)
        response.raise_for_status()
        data = response.json()

        for group in data.get('results', []):
            membership_criteria = group.get("expression", [])
            for expr in membership_criteria:
                if expr.get("resource_type") == "IPAddressExpression":
                    ipset_dyn_groups.append({
                        "id": group["id"],
                        "display_name": group.get("display_name"),
                        "description": group.get("description"),
                        "expression": membership_criteria,
                    })
                    break

        cursor = data.get("cursor")
        if cursor:
            params = {"cursor": cursor, "page_size": 1000}
        else:
            break

    return ipset_dyn_groups

def save_yaml(data, filename):
    with open(filename, "w") as f:
        yaml.dump(data, f, default_flow_style=False)

def load_yaml(filename):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            return yaml.safe_load(f) or []
    return []

def main():
    print("Collecting NSX-T IP set dynamic groups...")
    current_groups = get_sec_groups()

    if not os.path.exists(SEC_GROUPS_FILE):
        print("First run - creating groups YAML.")
        save_yaml(current_groups, SEC_GROUPS_FILE)
    else:
        print("Found existing YAML, comparing with current state...")
        prev_groups = load_yaml(SEC_GROUPS_FILE)
        prev_ids = {g["id"] for g in prev_groups}
        new_groups = [g for g in current_groups if g["id"] not in prev_ids]
        if new_groups:
            print(f"Found {len(new_groups)} new groups. Writing updates YAML.")
            save_yaml(new_groups, UPDATES_FILE)
            save_yaml(current_groups, SEC_GROUPS_FILE)
        else:
            print("No new groups detected.")

if __name__ == "__main__":
    main()
