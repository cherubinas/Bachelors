import json, os, tempfile, subprocess

class RuleManager:
    
# Function to initialize rule manager
    def __init__(self, rules_file="siem_rules.json"):
        self.rules_file = rules_file
        if not os.path.exists(self.rules_file):
            with open(self.rules_file, "w") as f: json.dump([], f, indent=2)
        self.rules = self.load_rules()
        
# Function to load rules
    def load_rules(self):
        with open(self.rules_file) as f: return json.load(f)
        
# Function to save rules
    def save_rules(self):
        with open(self.rules_file, "w") as f: json.dump(self.rules, f, indent=2)
        
# Function to add rules from JSON
    def add_rule_json(self, json_text):
        rule = json.loads(json_text)
        if "name" not in rule or "type" not in rule:
            raise ValueError("Rule must include 'name' and 'type'")
        if rule["type"] == "packet" and "match" not in rule:
            raise ValueError("Packet rules must include 'match'")
        if rule["type"] == "stateful" and "aggregate" not in rule:
            raise ValueError("Stateful rules must include 'aggregate'")
        self.rules.append(rule)
        
# Function to edit rules via nano for linux or notepad for windows
    def edit_rule_json(self, idx):
        if idx < 0 or idx >= len(self.rules): return None
        rule = self.rules[idx]
        tf = tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json')
        json.dump(rule, tf, indent=2)
        tf.close()

        editor = os.environ.get('EDITOR') or ('notepad' if os.name == 'nt' else 'nano')
        subprocess.run([editor, tf.name])

        try:
            with open(tf.name) as f:
                new_rule = json.load(f)
            if "name" not in new_rule or "type" not in new_rule:
                print("Validation error.")
                return None
            self.rules[idx] = new_rule
            return new_rule
        except Exception as e:
            print(f"Edit error: {e}")
            return None
        finally:
            os.unlink(tf.name)

 # Function to delete rules
    def delete_rule(self, idx):
        return self.rules.pop(idx) if 0 <= idx < len(self.rules) else None

# Rules management menu
    def menu(self):
        while True:
            print(f"\nRule Manager, total rules:{len(self.rules)}")
            for i, r in enumerate(self.rules, 1):
                print(f"  {i}) {r.get('name','<unnamed>')}")
            print("\n1) Add JSON rule\n2) Edit rule\n3) Delete rule\n4) Save & Return")

            c = input("Select option: ").strip()
            if c == "1":
                print("Paste full JSON (end with blank line):")
                lines = iter(lambda: input(), "")
                try:
                    self.add_rule_json("\n".join(lines))
                    print("Added.")
                except Exception as e:
                    print(f"Error: {e}")
            elif c == "2":
                try:
                    idx = int(input("Rule number: ")) - 1
                    print("Edited." if self.edit_rule_json(idx) else "Invalid.")
                except:
                    print("Invalid input.")
            elif c == "3":
                try:
                    idx = int(input("Rule number: ")) - 1
                    print("Deleted." if self.delete_rule(idx) else "Invalid.")
                except:
                    print("Invalid input.")
            elif c == "4":
                self.save_rules()
                break
            else:
                print("Invalid choice.")
