"""Seeded synthetic resource generator. Output: data/resources.json, data/context.json"""
import json, random
random.seed(42)
N = 600
ENV = [("dev", .40), ("staging", .25), ("prod", .35)]
DATA = {"dev": [("public", .35), ("internal", .45), ("confidential", .15), ("restricted", .05)],
        "staging": [("public", .20), ("internal", .45), ("confidential", .25), ("restricted", .10)],
        "prod": [("public", .15), ("internal", .30), ("confidential", .30), ("restricted", .25)]}
KIND = [("Deployment", .50), ("Database", .20), ("Bucket", .20), ("Volume", .10)]
def pick(opts):
    r, acc = random.random(), 0
    for v, p in opts:
        acc += p
        if r < acc: return v
    return opts[-1][0]
res, ctx = [], {}
for i in range(N):
    env = pick(ENV); data = pick(DATA[env]); kind = pick(KIND)
    name = f"{kind.lower()}-{i:04d}"
    tags = {"owner": "team-x", "cost-center": "cc-1"}
    if random.random() < .15: tags.pop("cost-center")
    spec = {"exposure": "public" if random.random() < .08 else "internal"}
    if kind == "Deployment":
        cs = []
        for _ in range(random.choice([1, 1, 2])):
            reg = "registry.internal.example" if random.random() > .15 else "docker.io/thirdparty"
            tag = "latest" if random.random() < .12 else "1.4.2"
            c = {"image": f"{reg}/svc:{tag}", "privileged": random.random() < .06}
            if random.random() > .25: c["limits"] = {"cpu": "500m", "memory": "512Mi"}
            cs.append(c)
        spec["containers"] = cs
    else:
        spec["encrypted"] = random.random() > .22
    res.append({"name": name, "kind": kind, "metadata": {"tags": tags}, "spec": spec})
    ctx[name] = {"env": env, "data_sensitivity": data,
                 "internet_facing": spec["exposure"] == "public" or (kind == "Deployment" and random.random() < .15),
                 "compensating_control": random.random() < .20}
json.dump(res, open("data/resources.json", "w"), indent=1)
json.dump(ctx, open("data/context.json", "w"), indent=1)
print(len(res), "resources")
