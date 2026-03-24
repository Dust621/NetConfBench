# PES-NetConfBench

A benchmark for evaluating LLMs on **BGP network configuration generation**. Given a network topology and a set of policy requirements in natural language, the model must produce complete, valid Cisco IOS configurations for every device.

## Dataset

**500 tasks** across 4 difficulty levels, 9 property types, and diverse topologies (3–5 ASes, 9–36 devices).

| Difficulty | Count | Description |
|---|---|---|
| L1 | 100 | Single requirement (export, isolation, reachability) |
| L2 | 126 | Single complex requirement (LP, MED, prepend, aggregation, community) |
| L3 | 185 | Two combined requirements |
| L4 | 89 | Three combined requirements |

**Property types** (total 863 across 500 tasks):

| Type | Count | Description |
|---|---|---|
| export_constraint | 168 | Deny/permit prefix advertisement to specific AS |
| community_tagging | 151 | Set BGP community on specific prefix |
| path_preference | 108 | Prefer specific egress point (mechanism-agnostic) |
| route_aggregation | 99 | Aggregate prefixes with summary-only |
| med_manipulation | 87 | Control ingress path via MED |
| isolation | 72 | Ensure no route to specific prefix |
| no_transit | 61 | Prevent AS from transiting traffic |
| local_preference | 60 | Control egress via BGP local-preference |
| as_path_prepend | 57 | AS path prepending with routing effect |

## Topologies

**50 topologies** across 4 categories, each with a network diagram in `topology_diagrams/`:

| Category | Count | Topologies | ASes | Devices |
|---|---|---|---|---|
| Small | 8 | small_1 – small_8 | 3 | 9–12 |
| Medium | 9 | medium_1 – medium_9 | 4–5 | 15–24 |
| Large | 8 | large_1 – large_8 | 5 | 24–36 |
| Zoo (real-world ISPs) | 25 | zoo_Airtel, zoo_Sprint, ... | 3–5 | 9–36 |

Each task references one of these 50 topologies. Diagrams show AS boundaries, router roles (border/internal), eBGP peering links, and IGP connections.

## Directory Structure

```
benchmark/
├── README.md
├── system_prompt.txt              # System prompt for the LLM
├── verify.py                      # Standalone verification script
├── prompts/                       # 500 task prompts (natural language)
│   ├── task_000.txt
│   └── ...
├── metadata/                      # Verification data (NOT shown to LLM)
│   ├── task_000.json
│   └── ...
├── topology_diagrams/             # Network topology visualizations (50 topologies)
│   ├── small_1.png ... small_8.png
│   ├── medium_1.png ... medium_9.png
│   ├── large_1.png ... large_8.png
│   └── zoo_*.png                  # 25 real-world ISP topologies from Topology Zoo
└── verifier/                      # Batfish verification engine
    ├── __init__.py
    ├── verifier.py                # Property verification (9 types)
    ├── batfish_adapter.py         # Batfish query wrapper
    ├── schemas.py                 # Data models (PropertyIR, TopologyContext, etc.)
    └── prefix_resolver.py         # Prefix selector → CIDR resolution
```

## Quick Start

### 1. Generate Configs

Feed `system_prompt.txt` as the system message and any `prompts/task_xxx.txt` as the user message to your LLM.

The model should output configs in this format:

```
=== CONFIG: AS1_R1 ===
hostname AS1_R1
!
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
...
end
=== END CONFIG ===
```

### 2. Prepare Output

Organize outputs in one of two formats:

**Option A: Config directory** (recommended, Batfish-native)
```
output/
  task_000/
    configs/
      AS1_R1.cfg
      AS1_R2.cfg
      ...
  task_001/
    configs/
      ...
```

**Option B: Raw text file**
```
output/
  task_000/
    raw_output.txt    # Contains === CONFIG === markers
  task_001/
    raw_output.txt
```

### 3. Verify

**Prerequisites:**
- Python 3.9+
- A running [Batfish](https://github.com/batfish/batfish) server
- `pip install pybatfish pandas pydantic`

**Single task:**
```bash
# From config directory
python verify.py --metadata-dir metadata/ --task-id task_000 \
    --config-dir output/task_000/configs/ --batfish-host <BATFISH_IP>

# From raw text file
python verify.py --metadata-dir metadata/ --task-id task_000 \
    --config-file output/task_000/raw_output.txt --batfish-host <BATFISH_IP>
```

**Batch verification:**
```bash
python verify.py --metadata-dir metadata/ \
    --output-dir output/ --batfish-host <BATFISH_IP>
```

### 4. Results

Single task output:
```
Task: task_000 (9 devices)
  [PASS] Connectivity (eBGP 6/6, iBGP 12/12, reachability 4/4)
  [PASS] prop_4 (route_aggregation)
  [PASS] prop_5 (community_tagging)
  [PASS] prop_6 (export_constraint)

Result: ALL PASS (3/3 properties)
```

Batch mode writes `verification_results.jsonl` with per-task JSON:
```json
{
  "task_id": "task_000",
  "difficulty": "L4",
  "connectivity": {"pass": true, "ebgp": "6/6", "ibgp": "12/12", "reachability": "4/4"},
  "properties_total": 3,
  "properties_pass": 3,
  "all_pass": true,
  "property_results": [...]
}
```

## Verification Details

Each task is verified on three levels:

1. **Connectivity gate** — eBGP sessions established, iBGP sessions established, cross-AS Loopback0 reachability
2. **Property verification** — each requirement checked via Batfish queries (BGP RIB, routing table, traceroute, etc.)
3. **Overall pass** — connectivity gate + all properties must pass

A task is **ALL PASS** only if connectivity and every property passes.

## Prompt Design

- `prompts/task_xxx.txt` contains the **full task description**: topology (ASes, devices, interfaces, IPs, eBGP/IGP links, prefix origins) and requirements in natural language.
- Requirements are **intent-based** — they describe *what* should happen, not *how*. For example:
  - `"Ensure AS4_R1 prefers egress via AS4_R5 over AS4_R3 for prefix 10.5.2.0/24."` (no mechanism specified)
  - `"Ensure AS2 does not advertise prefix 10.3.2.0/24 to AS1."` (not "configure route-map")
- `metadata/task_xxx.json` contains structured `properties` and `topo_ctx` used only for verification — these are **never shown to the LLM**.
