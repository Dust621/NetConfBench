"""
Prefix Selector Resolver
- Expands prefix_selector to concrete CIDR lists
- Deterministic prefix allocation: 10.{as}.{role_id}.0/24
"""
from typing import List, Dict, Any
from .schemas import PrefixRole, TopologyContext


class PrefixResolver:
    """Resolves prefix selectors from Property IR to concrete CIDRs"""

    @staticmethod
    def _normalize_as_num(as_num, topo_ctx: TopologyContext) -> int:
        """Normalize as_num to int, handling string from template substitution"""
        as_num_int = int(as_num) if isinstance(as_num, str) else as_num
        if as_num_int in topo_ctx.external_prefixes:
            return as_num_int
        return as_num

    @staticmethod
    def _resolve_role(as_num, role: str, topo_ctx: TopologyContext) -> str:
        """Resolve single role to CIDR"""
        as_num = PrefixResolver._normalize_as_num(as_num, topo_ctx)
        return topo_ctx.external_prefixes[as_num][role]

    @staticmethod
    def _resolve_roles(as_num, roles: list[str], topo_ctx: TopologyContext) -> list[str]:
        """Resolve multiple roles to CIDR list"""
        as_num = PrefixResolver._normalize_as_num(as_num, topo_ctx)
        return [topo_ctx.external_prefixes[as_num][role] for role in roles]

    @staticmethod
    def _resolve_any_external(as_num, topo_ctx: TopologyContext) -> list[str]:
        """Resolve to all external prefixes of an AS"""
        as_num = PrefixResolver._normalize_as_num(as_num, topo_ctx)
        return [
            topo_ctx.external_prefixes[as_num][role]
            for role in [PrefixRole.CUST.value, PrefixRole.SERV.value, PrefixRole.BLK.value]
        ]

    @staticmethod
    def resolve(
        selector: Dict[str, Any], topo_ctx: TopologyContext
    ) -> tuple[List[str], Dict[str, Any]]:
        """
        Resolve prefix selector to CIDR list
        Returns: (cidr_list, resolution_record)
        """
        selector_type = selector['type']

        if selector_type == 'external_role':
            as_num = selector['as_num']
            role = selector['role']
            cidr = PrefixResolver._resolve_role(as_num, role, topo_ctx)
            return [cidr], {
                'type': 'external_role',
                'as_num': as_num,
                'role': role,
                'resolved': [cidr]
            }

        elif selector_type == 'external_roles':
            as_num = selector['as_num']
            roles = selector['roles']
            cidrs = PrefixResolver._resolve_roles(as_num, roles, topo_ctx)
            return cidrs, {
                'type': 'external_roles',
                'as_num': as_num,
                'roles': roles,
                'resolved': cidrs
            }

        elif selector_type == 'any_external':
            as_num = selector['as_num']
            cidrs = PrefixResolver._resolve_any_external(as_num, topo_ctx)
            return cidrs, {
                'type': 'any_external',
                'as_num': as_num,
                'resolved': cidrs
            }

        elif selector_type == 'cidr':
            cidr = selector['cidr']
            return [cidr], {
                'type': 'cidr',
                'resolved': [cidr]
            }

        elif selector_type == 'cidr_list':
            cidr_list = selector['cidr_list']
            return cidr_list, {
                'type': 'cidr_list',
                'resolved': cidr_list
            }

        else:
            raise ValueError(f"Unknown prefix selector type: {selector_type}")

    @staticmethod
    def resolve_property_prefixes(
        property_ir: Dict[str, Any], topo_ctx: TopologyContext
    ) -> Dict[str, List[str]]:
        """
        Resolve all prefix selectors in a property
        Returns: {selector_key: [cidrs]}
        """
        resolved = {}
        predicate = property_ir.get('predicate', {})

        for key in ['prefix', 'prefixes', 'dst_prefix', 'src_prefix']:
            if key in predicate:
                selector = predicate[key]
                if isinstance(selector, dict) and 'type' in selector:
                    cidrs, _ = PrefixResolver.resolve(selector, topo_ctx)
                    resolved[key] = cidrs

        if 'components' in predicate and isinstance(predicate['components'], list):
            comp_cidrs = []
            for comp in predicate['components']:
                if isinstance(comp, dict) and 'type' in comp:
                    try:
                        cidrs, _ = PrefixResolver.resolve(comp, topo_ctx)
                        comp_cidrs.extend(cidrs)
                    except (ValueError, KeyError):
                        pass
            if comp_cidrs:
                resolved['components'] = comp_cidrs

        return resolved
