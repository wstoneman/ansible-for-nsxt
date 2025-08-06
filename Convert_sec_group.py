import yaml
import json
import sys
from pathlib import Path

def parse_expression_list(expr_list):
    """
    Given an 'expression' list, parses it into grouped 'criteria'
    with proper 'conjunction_operator' and grouped expressions.
    """
    criteria_blocks = []
    buffer = []
    current_conj = "AND"  # Default unless overridden

    for item in expr_list:
        if item["resource_type"] == "ConjunctionOperator":
            current_conj = item["conjunction_operator"]
        else:
            buffer.append(item)

    # In most YAMLs, either everything is in one NestedExpression or
    # alternated with ConjunctionOperators
    if buffer and all(e["resource_type"] == "NestedExpression" for e in buffer) and len(buffer) > 1:
        # Multiple NestedExpressions with a top-level OR
        criteria_blocks.append({
            "conjunction_operator": current_conj,
            "expressions": buffer
        })
    else:
        # Single criterion — wrap directly
        for entry in buffer:
            criteria_blocks.append({
                "conjunction_operator": "AND",
                "expressions": [entry]
            })

    return criteria_blocks

def load_yaml_file(path):
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def build_group_json(yaml_data):
    output = {}
    for group in yaml_data.get("sec_groups", []):
        group_id = group["id"]
        group_data = {
            "display_name": group["display_name"],
            "criteria": []
        }

        expr = group.get("expression", [])
        group_data["criteria"] = parse_expression_list(expr)

        output[group_id] = group_data
    return output

def main(input_file, output_file=None):
    yaml_data = load_yaml_file(input_file)
    parsed = build_group_json(yaml_data)

    output_json = json.dumps(parsed, indent=2)

    if output_file:
        with open(output_file, 'w') as f:
            f.write(output_json)
        print(f"✅ Output written to: {output_file}")
    else:
        print(output_json)

if __name__ == "__main__":
    # Example:
    # python process_nsxt_secgroups.py input_test_file.yaml.txt parsed_secgroups.json
    if len(sys.argv) < 2:
        print("Usage: python process_nsxt_secgroups.py <input_yaml> [output_json]")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None

    main(input_path, output_path)
