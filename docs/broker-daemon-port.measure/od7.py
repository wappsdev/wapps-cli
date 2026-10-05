"""OD7: how much of a role differs between enrolled projects. Read-only."""
import json, hashlib, pathlib, collections
root = pathlib.Path.home() / ".agent-broker" / "projects"
tools = collections.defaultdict(set); spec = collections.defaultdict(set); prompts = collections.defaultdict(lambda: collections.defaultdict(set)); skills=collections.defaultdict(set)
projects = sorted(p for p in root.iterdir() if (p / "roles.json").is_file())
for p in projects:
    for name, role in json.load(open(p / "roles.json"))["roles"].items():
        for prov, v in role["variants"].items():
            k = f"{name}.{prov}"
            tools[k].add(frozenset(v["tools"])); spec[k].add((v["model"], v["effort"])); skills[k].add(tuple(v.get("skills", [])))
            f = p / v["prompt"]
            if f.is_file(): prompts[v["prompt"]][hashlib.sha256(f.read_bytes()).hexdigest()[:12]].add(p.name)
print("projects with roles.json:", len(projects), [p.name for p in projects])
print("(role, provider) keys:", len(tools))
print("keys whose tool SET agrees across projects:", sum(len(v) == 1 for v in tools.values()), "of", len(tools))
print("keys whose (model,effort) differ:", sorted(k for k, v in spec.items() if len(v) > 1))
print("keys whose skills differ:", sorted(k for k, v in skills.items() if len(v) > 1))
for pr, d in sorted(prompts.items()):
    n = sum(len(x) for x in d.values())
    print(f"prompt {pr}: {len(d)} distinct contents across {n} projects")
