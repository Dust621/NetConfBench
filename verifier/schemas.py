"""
Core data schemas for benchmark verification
"""
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Literal, Optional, Any, Tuple
from enum import Enum
import json


def parse_edge_key(key: str) -> Tuple[int, int, int]:
    """Parse edge key string to (as1, as2, link_idx).
    Formats: "1,3" -> (1,3,0), "1,3_2" -> (1,3,1), "1,3_3" -> (1,3,2)
    """
    if '_' in key:
        base, suffix = key.rsplit('_', 1)
        as1, as2 = map(int, base.split(','))
        return as1, as2, int(suffix) - 1
    else:
        as1, as2 = map(int, key.split(','))
        return as1, as2, 0


def format_edge_key(as1: int, as2: int, link_idx: int = 0) -> str:
    """Format (as1, as2, link_idx) to edge key string.
    link_idx=0 -> "1,3", link_idx=1 -> "1,3_2", link_idx=2 -> "1,3_3"
    """
    base = f"{as1},{as2}"
    if link_idx == 0:
        return base
    return f"{base}_{link_idx + 1}"


# ============================================================================
# Enums
# ============================================================================

class PrefixRole(str, Enum):
    """External prefix roles per AS"""
    CUST = "CUST"  # Customer prefix: 10.i.1.0/24
    SERV = "SERV"  # Service prefix: 10.i.2.0/24
    BLK = "BLK"    # Blocked prefix: 10.i.3.0/24


class PropertyType(str, Enum):
    """Property types for verification (9 types used in the benchmark)"""
    EXPORT_CONSTRAINT = "export_constraint"
    NO_TRANSIT = "no_transit"
    PATH_PREFERENCE = "path_preference"
    ISOLATION = "isolation"
    ROUTE_AGGREGATION = "route_aggregation"
    AS_PATH_PREPEND = "as_path_prepend"
    LOCAL_PREFERENCE = "local_preference"
    MED_MANIPULATION = "med_manipulation"
    COMMUNITY_TAGGING = "community_tagging"


class VerificationStatus(str, Enum):
    """Verification result status"""
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"


# ============================================================================
# Prefix Selector Schema
# ============================================================================

@dataclass
class PrefixSelector:
    """
    Structured prefix selector for Property IR
    Supports: external_role, external_roles, cidr, cidr_list, any_external
    """
    type: Literal["external_role", "external_roles", "cidr", "cidr_list", "any_external"]
    as_num: Optional[int] = None
    role: Optional[str] = None
    roles: Optional[List[str]] = None
    cidr: Optional[str] = None
    cidr_list: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


# ============================================================================
# Property IR Schema
# ============================================================================

@dataclass
class PropertyIR:
    """
    Property Intermediate Representation
    - Unifies "human intent" into structured, verifiable properties
    - Maps deterministically to Batfish queries
    """
    id: str
    type: PropertyType
    scope: Dict[str, Any]  # {"at": node_or_as, "src": node, "dst": node, ...}
    predicate: Dict[str, Any]  # Property-specific conditions
    expect: bool  # True = must hold, False = must not hold
    priority: int  # 0 = sanity check, 1 = critical, 2 = normal
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['type'] = self.type.value if isinstance(self.type, Enum) else self.type
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PropertyIR':
        """Create PropertyIR from dictionary"""
        if isinstance(data.get('type'), str):
            data = data.copy()
            data['type'] = PropertyType(data['type'])
        return cls(**data)


# ============================================================================
# Topology Context
# ============================================================================

@dataclass
class TopologyContext:
    """
    Complete topology context for task verification
    """
    topo_id: str
    seed: int

    # AS-level topology
    as_list: List[int]
    as_borders: Dict[int, List[str]]  # AS -> [border node names]
    as_edges: List[tuple[int, int]]  # [(AS1, AS2), ...]

    # Node-level information
    nodes: List[str]  # All node names
    node_to_as: Dict[str, int]  # Node -> AS mapping
    node_loopback: Dict[str, str]  # Node -> loopback IP (1.1.1.1/32 style)
    ip_to_node: Dict[str, str]  # Interface IP -> Node (for preference mapping)

    # External prefixes (deterministic allocation)
    external_prefixes: Dict[int, Dict[str, str]]  # AS -> {role -> CIDR}
    prefix_origin: Dict[int, Dict[str, str]]  # AS -> {role -> origin_node}

    # AS internal structure
    as_core_nodes: Dict[int, List[str]]  # AS -> [core nodes] (for RR)
    as_igp_edges: Dict[int, List[tuple[str, str]]]  # AS -> [(node1, node2), ...]

    # AS edge assignments (for eBGP link generation)
    # Key format: "as1,as2" (1st link), "as1,as2_2" (2nd link), "as1,as2_3" (3rd link)
    as_edge_assignments: Dict[str, tuple[str, str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if 'as_edge_assignments' in data and data['as_edge_assignments']:
            converted = {}
            for k, v in data['as_edge_assignments'].items():
                if isinstance(k, tuple):
                    converted[f"{k[0]},{k[1]}"] = v
                else:
                    converted[k] = v
            data['as_edge_assignments'] = converted
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TopologyContext':
        data = dict(data)  # shallow copy to avoid mutating state["topo_ctx"] in place
        if 'as_edge_assignments' in data and isinstance(data['as_edge_assignments'], dict):
            converted = {}
            for k, v in data['as_edge_assignments'].items():
                if isinstance(k, tuple):
                    converted[format_edge_key(int(k[0]), int(k[1]))] = tuple(v)
                elif isinstance(k, str):
                    converted[k] = tuple(v) if isinstance(v, list) else v
            data['as_edge_assignments'] = converted

        for field_name in ['as_borders', 'external_prefixes', 'prefix_origin', 'as_core_nodes', 'as_igp_edges']:
            if field_name in data and isinstance(data[field_name], dict):
                data[field_name] = {
                    int(k) if isinstance(k, str) and k.isdigit() else k: v
                    for k, v in data[field_name].items()
                }

        return cls(**data)


# ============================================================================
# Verifier Result Schema
# ============================================================================

@dataclass
class CounterExample:
    """Concrete counterexample from Batfish"""
    description: str
    details: Dict[str, Any]


@dataclass
class VerifierResult:
    """
    Unified verification result
    """
    property_id: str
    status: VerificationStatus

    # For FAIL status
    counterexample: Optional[CounterExample] = None
    blame_nodes: List[str] = field(default_factory=list)
    repair_hint: Optional[str] = None

    # For ERROR status
    error_message: Optional[str] = None

    # Artifacts (for auditing)
    resolved_prefixes: Dict[str, List[str]] = field(default_factory=dict)
    query_details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['status'] = self.status.value if isinstance(self.status, Enum) else self.status
        return data
