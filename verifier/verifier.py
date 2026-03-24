"""
Verifier: Property IR → Batfish verification
- Maps each PropertyType to Batfish queries
- Generates counterexamples on failure
- Provides repair hints
"""
from typing import List, Dict, Any, Optional
from .schemas import (
    PropertyIR, PropertyType, VerifierResult, VerificationStatus,
    CounterExample, TopologyContext
)
from .prefix_resolver import PrefixResolver
from .batfish_adapter import BatfishAdapter


class PropertyVerifier:
    """
    Verifies properties using Batfish
    - Deterministic mapping: Property IR → Batfish queries
    - Generates structured counterexamples
    """

    def __init__(self, bf_adapter: BatfishAdapter):
        self.bf = bf_adapter

    @staticmethod
    def _normalize_node_name(node_name: Optional[str]) -> Optional[str]:
        """Normalize node name to lowercase for Batfish queries"""
        return node_name.lower() if node_name else None

    @staticmethod
    def _get_as_borders(topo_ctx: 'TopologyContext', as_num) -> List[str]:
        """Get border nodes for an AS, handling int/str key mismatch."""
        borders = topo_ctx.as_borders.get(as_num)
        if borders is None:
            borders = topo_ctx.as_borders.get(int(as_num) if isinstance(as_num, str) else str(as_num), [])
        return borders

    @staticmethod
    def _reachable_ases_excluding_edge(
        as_edges: List, from_as: int, to_as: int
    ) -> set:
        """BFS from from_as excluding the direct from_as↔to_as edge."""
        from collections import deque
        adj = {}
        for edge in (as_edges or []):
            a, b = int(edge[0]), int(edge[1])
            if (a == from_as and b == to_as) or (a == to_as and b == from_as):
                continue
            adj.setdefault(a, set()).add(b)
            adj.setdefault(b, set()).add(a)
        visited = set()
        queue = deque([from_as])
        while queue:
            node = queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            for neighbor in adj.get(node, []):
                if neighbor not in visited:
                    queue.append(neighbor)
        visited.discard(from_as)
        return visited

    @staticmethod
    def _create_batfish_error_result(
        prop_id: str,
        error_type: str,
        error_details: str,
        batfish_output: Optional[str] = None
    ) -> VerifierResult:
        """Create a VerifierResult for Batfish runtime errors."""
        error_message = f"[BATFISH {error_type}] {error_details}"

        if batfish_output:
            error_message += f"\n\nBatfish Output:\n{batfish_output}"

        error_message += (
            "\n\nIMPORTANT: This is a Batfish tool error, NOT a configuration logic error. "
            "Do NOT attempt to fix configurations based on this error. "
            "Possible causes: parsing failures, unsupported syntax, Batfish bugs, server issues."
        )

        return VerifierResult(
            property_id=prop_id,
            status=VerificationStatus.ERROR,
            error_message=error_message,
            resolved_prefixes={}
        )

    def _route_not_found_context(self, prefix, at_node, topo_ctx):
        origin_as = None
        origin_node = None
        for as_num, roles in topo_ctx.external_prefixes.items():
            for role, cidr in roles.items():
                if cidr == prefix:
                    origin_as = as_num
                    origin_node = topo_ctx.prefix_origin.get(as_num, {}).get(role)
                    break
            if origin_as is not None:
                break

        if origin_as is None or origin_node is None:
            return None, None, {}

        target_as = topo_ctx.node_to_as.get(at_node.upper()) or topo_ctx.node_to_as.get(at_node)
        extra_details = {"origin_as": origin_as, "origin_node": origin_node, "target_as": target_as}
        origin_node_lower = origin_node.lower()

        if target_as == origin_as:
            hint = (
                f"Prefix {prefix} originated by {origin_node} (AS{origin_as}). "
                f"Check: 1) {origin_node} has 'network' statement + static null route for {prefix}, "
                f"2) iBGP full mesh within AS{origin_as}"
            )
            blame = list(dict.fromkeys([origin_node_lower, at_node]))
        else:
            origin_borders = [b.lower() for b in self._get_as_borders(topo_ctx, origin_as)]
            target_borders = [b.lower() for b in self._get_as_borders(topo_ctx, target_as)]
            hint = (
                f"Prefix {prefix} originated by {origin_node} (AS{origin_as}), target {at_node} (AS{target_as}). "
                f"Check: 1) {origin_node} has 'network' statement + static null route for {prefix}, "
                f"2) eBGP sessions between AS{origin_as} and AS{target_as} borders, "
                f"3) next-hop-self on AS{target_as} border routers {target_borders}, "
                f"4) iBGP within AS{target_as}"
            )
            blame = list(dict.fromkeys(
                [origin_node_lower] + origin_borders + target_borders + [at_node]
            ))

        return hint, blame, extra_details

    def verify_property(
        self,
        prop: PropertyIR,
        topo_ctx: TopologyContext
    ) -> VerifierResult:
        """Verify a single property."""
        # Check snapshot parse status first
        parse_success, parse_status = self.bf.get_snapshot_parse_status()

        if not parse_success:
            return self._create_batfish_error_result(
                prop_id=prop.id,
                error_type="CONNECTION_ERROR",
                error_details="Failed to query Batfish snapshot parse status. Check Batfish server connectivity.",
                batfish_output=str(parse_status.get('error', 'Unknown error'))
            )

        if parse_status.get('failed'):
            failed_files = parse_status['failed']
            error_details = (
                f"Configuration parsing failed for {len(failed_files)} file(s): {failed_files}. "
                f"Common issues: invalid syntax, unsupported commands, non-standard interface names."
            )

            batfish_details = ""
            try:
                q = self.bf.session.q.parseWarning()
                answer = q.answer(snapshot=self.bf.current_snapshot)
                warnings_df = answer.frame()

                if not warnings_df.empty:
                    batfish_details = f"\nParse Warnings ({len(warnings_df)} total):\n"
                    for idx, row in warnings_df.head(10).iterrows():
                        filename = row.get('Filename', 'Unknown')
                        line = row.get('Line', '?')
                        text = row.get('Text', 'N/A')
                        batfish_details += f"  {filename}:{line} - {text}\n"
                    if len(warnings_df) > 10:
                        batfish_details += f"  ... and {len(warnings_df) - 10} more warnings\n"
            except Exception as e:
                batfish_details = f"\nCould not retrieve detailed parse errors: {e}"

            return self._create_batfish_error_result(
                prop_id=prop.id,
                error_type="PARSE_ERROR",
                error_details=error_details,
                batfish_output=batfish_details
            )

        if parse_success:
            total = parse_status.get('total_files', 0)
            parsed = len(parse_status.get('parsed', []))

            if total > 0 and parsed == 0:
                return self._create_batfish_error_result(
                    prop_id=prop.id,
                    error_type="PARSE_ERROR",
                    error_details=(
                        f"CRITICAL: None of {total} config files were successfully parsed. "
                        f"This is likely due to unsupported syntax or non-standard interface names. "
                        f"Verification cannot proceed without valid parsed configs."
                    )
                )

        # Resolve prefixes first
        resolved_prefixes = PrefixResolver.resolve_property_prefixes(
            prop.to_dict(), topo_ctx
        )

        # Dispatch to specific verifier
        dispatch = {
            PropertyType.EXPORT_CONSTRAINT: self._verify_export_constraint,
            PropertyType.NO_TRANSIT: self._verify_no_transit,
            PropertyType.PATH_PREFERENCE: self._verify_path_preference,
            PropertyType.ISOLATION: self._verify_isolation,
            PropertyType.ROUTE_AGGREGATION: self._verify_route_aggregation,
            PropertyType.AS_PATH_PREPEND: self._verify_as_path_prepend,
            PropertyType.LOCAL_PREFERENCE: self._verify_local_preference,
            PropertyType.MED_MANIPULATION: self._verify_med_manipulation,
            PropertyType.COMMUNITY_TAGGING: self._verify_community_tagging,
        }

        handler = dispatch.get(prop.type)
        if handler:
            return handler(prop, topo_ctx, resolved_prefixes)

        return VerifierResult(
            property_id=prop.id,
            status=VerificationStatus.ERROR,
            error_message=f"Unsupported property type: {prop.type}"
        )

    def verify_connectivity(
        self, topo_ctx: TopologyContext
    ) -> Dict[str, Any]:
        """
        Connectivity gate: verify basic network infrastructure before property checks.
        Checks:
        1. eBGP sessions — all expected eBGP links are established
        2. iBGP sessions — all configured iBGP sessions are established
        3. Cross-AS reachability — sample loopback-to-loopback traceroutes
        """
        result = {
            "connectivity_pass": True,
            "ebgp_sessions": {"expected": 0, "established": 0, "missing": []},
            "ibgp_sessions": {"total": 0, "established": 0, "not_established": 0, "failed_sessions": []},
            "reachability_checks": {"total": 0, "passed": 0, "failed": []},
            "issues": [],
        }

        # 1. Check eBGP sessions
        expected_sessions = []
        for key, nodes_pair in (topo_ctx.as_edge_assignments or {}).items():
            if isinstance(key, str):
                parts = key.replace('_', ',').split(',')
                as1, as2 = int(parts[0]), int(parts[1])
            else:
                as1, as2 = key
            local_node, remote_node = nodes_pair[0], nodes_pair[1]
            expected_sessions.append((local_node.lower(), remote_node.lower(), as1, as2))

        result["ebgp_sessions"]["expected"] = len(expected_sessions)

        success, edges_df, error = self.bf.query_bgp_edges()
        if not success:
            result["connectivity_pass"] = False
            result["ebgp_sessions"]["error"] = f"BGP edges query failed: {error}"
            return result

        established_pairs = set()
        if not edges_df.empty:
            for _, row in edges_df.iterrows():
                local = str(row.get("Node", "")).lower()
                remote = str(row.get("Remote_Node", "")).lower()
                established_pairs.add((local, remote))

        for local_node, remote_node, as1, as2 in expected_sessions:
            if (local_node, remote_node) in established_pairs or \
               (remote_node, local_node) in established_pairs:
                result["ebgp_sessions"]["established"] += 1
            else:
                result["ebgp_sessions"]["missing"].append({
                    "local": local_node, "remote": remote_node,
                    "as_pair": f"AS{as1}-AS{as2}"
                })
                result["issues"].append({
                    "type": "ebgp_session_down",
                    "severity": "CRITICAL",
                    "blame_nodes": [local_node, remote_node],
                    "description": (
                        f"eBGP session between {local_node} (AS{as1}) and "
                        f"{remote_node} (AS{as2}) is NOT established."
                    ),
                    "repair_hint": (
                        f"Check on BOTH {local_node} and {remote_node}: "
                        f"1) 'router bgp' with correct AS number, "
                        f"2) 'neighbor' statement with correct remote IP and remote-as, "
                        f"3) Interface IP addresses on the eBGP link are correctly configured and 'no shutdown', "
                        f"4) 'update-source' if using loopback for peering."
                    ),
                })

        if result["ebgp_sessions"]["missing"]:
            result["connectivity_pass"] = False

        # 2. iBGP session check via bgpSessionStatus
        from collections import defaultdict
        ibgp_success, ibgp_df, ibgp_error = self.bf.query_bgp_session_status()
        if ibgp_success and not ibgp_df.empty:
            ibgp_rows = ibgp_df[ibgp_df["Session_Type"] == "IBGP"]
            result["ibgp_sessions"]["total"] = len(ibgp_rows)
            established_rows = ibgp_rows[ibgp_rows["Established_Status"] == "ESTABLISHED"]
            not_est_rows = ibgp_rows[ibgp_rows["Established_Status"] != "ESTABLISHED"]
            result["ibgp_sessions"]["established"] = len(established_rows)
            result["ibgp_sessions"]["not_established"] = len(not_est_rows)

            if len(not_est_rows) > 0:
                result["connectivity_pass"] = False
                as_failed = defaultdict(list)
                for _, row in not_est_rows.iterrows():
                    local = str(row.get("Node", ""))
                    remote = str(row.get("Remote_Node", "") or "?")
                    local_ip = str(row.get("Local_IP", ""))
                    remote_ip = str(row.get("Remote_IP", ""))
                    status = str(row.get("Established_Status", ""))
                    local_as = str(row.get("Local_AS", ""))
                    result["ibgp_sessions"]["failed_sessions"].append({
                        "local": local, "remote": remote,
                        "local_ip": local_ip, "remote_ip": remote_ip,
                        "status": status,
                    })
                    as_failed[local_as].append(f"{local} -> {remote} ({local_ip} -> {remote_ip})")

                for asn, sessions in as_failed.items():
                    result["issues"].append({
                        "type": "ibgp_session_down",
                        "severity": "CRITICAL",
                        "blame_nodes": list({s.split(" -> ")[0] for s in sessions}),
                        "description": (
                            f"AS{asn}: {len(sessions)} iBGP session(s) NOT established: "
                            + "; ".join(sessions[:5])
                            + (f" ... and {len(sessions)-5} more" if len(sessions) > 5 else "")
                        ),
                        "repair_hint": (
                            f"Check AS{asn}: 1) IGP (OSPF/IS-IS) is configured on all intra-AS links "
                            f"so loopback addresses are reachable, "
                            f"2) iBGP 'neighbor' statements have correct remote IP and remote-as, "
                            f"3) 'update-source Loopback0' is set on iBGP neighbors."
                        ),
                    })
        elif not ibgp_success:
            result["ibgp_sessions"]["error"] = f"bgpSessionStatus query failed: {ibgp_error}"

        # 3. Cross-AS reachability: bidirectional check per AS pair
        checked_pairs = set()
        for local_node, remote_node, as1, as2 in expected_sessions:
            pair_key = (min(as1, as2), max(as1, as2))
            if pair_key in checked_pairs:
                continue
            checked_pairs.add(pair_key)

            checks = []
            for src, dst, src_as, dst_as in [
                (local_node, remote_node, as1, as2),
                (remote_node, local_node, as2, as1),
            ]:
                dst_ip = topo_ctx.node_loopback.get(
                    dst.upper(), topo_ctx.node_loopback.get(dst, "")
                ).split('/')[0]
                if dst_ip:
                    checks.append((src, dst, dst_ip, src_as, dst_as))

            for src, dst, dst_ip, src_as, dst_as in checks:
                result["reachability_checks"]["total"] += 1
                q_success, reachable, _ = self.bf.query_reachability(
                    src, dst_ip, expected_disposition="ACCEPTED"
                )
                if q_success and reachable:
                    result["reachability_checks"]["passed"] += 1
                else:
                    result["connectivity_pass"] = False
                    result["reachability_checks"]["failed"].append({
                        "src": src, "dst": dst,
                        "dst_ip": dst_ip, "as_pair": f"AS{src_as}-AS{dst_as}"
                    })
                    hint = (
                        f"Cross-AS reachability failure from {src} (AS{src_as}) to "
                        f"{dst} (AS{dst_as}, loopback {dst_ip}). Check: "
                        f"1) eBGP session between AS{src_as} and AS{dst_as} is UP, "
                        f"2) 'next-hop-self' is set on iBGP neighbors within AS{src_as}, "
                        f"3) BGP 'network' statement for {dst_ip} on {dst}, "
                        f"4) No outbound route-map blocking loopback/prefix advertisements."
                    )
                    result["issues"].append({
                        "type": "reachability_failure",
                        "severity": "CRITICAL",
                        "blame_nodes": [src, dst],
                        "description": (
                            f"{dst} (loopback {dst_ip}) is NOT reachable from {src}."
                        ),
                        "repair_hint": hint,
                    })

        return result

    def _sender_has_prefix(
        self,
        from_borders_lower: list,
        prefix: str
    ) -> bool:
        """Check if any from_as border router has the prefix in its BGP RIB."""
        from_pattern = f"/({'|'.join(from_borders_lower)})/"
        success, df, _ = self.bf.query_routes(
            nodes=from_pattern, network=prefix, rib="bgp"
        )
        return success and not df.empty

    def _verify_export_constraint(
        self,
        prop: PropertyIR,
        topo_ctx: TopologyContext,
        resolved_prefixes: Dict[str, List[str]]
    ) -> VerifierResult:
        """
        Verify export_constraint property using bidirectional verification:
        1. Receiver-side: check to_as BGP RIB for route from from_as (best-path only)
        2. Sender-side fallback: check from_as has prefix + eBGP session up
        """
        from_as = prop.scope.get("from_as")
        to_as = prop.scope.get("to_as")
        action = prop.predicate.get("action", "deny")
        prefixes = resolved_prefixes.get("prefix", [])

        if not prefixes:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.ERROR,
                error_message="Failed to resolve prefix",
                resolved_prefixes=resolved_prefixes
            )

        prefix = prefixes[0]

        from_borders = self._get_as_borders(topo_ctx, from_as)
        to_borders = self._get_as_borders(topo_ctx, to_as)

        if not from_borders or not to_borders:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.ERROR,
                error_message=f"No border nodes found for AS{from_as} or AS{to_as}",
                resolved_prefixes=resolved_prefixes
            )

        from_borders_lower = [b.lower() for b in from_borders]
        to_borders_lower = [b.lower() for b in to_borders]

        # --- Step 1: Receiver-side check (best-path) ---
        to_pattern = f"/({'|'.join(to_borders_lower)})/"
        success, df, error = self.bf.query_routes(
            nodes=to_pattern, network=prefix, rib="bgp"
        )

        if not success:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.ERROR,
                error_message=f"Batfish query failed: {error}",
                resolved_prefixes=resolved_prefixes
            )

        from_borders_set = set(from_borders_lower)
        received_from_src = False
        best_as_path = ""
        if not df.empty:
            for _, route in df.iterrows():
                nh_ip = str(route.get('Next_Hop_IP', ''))
                nh_node = topo_ctx.ip_to_node.get(nh_ip, '')
                if nh_node.lower() in from_borders_set:
                    received_from_src = True
                    break
                as_path = str(route.get('AS_Path', ''))
                best_as_path = as_path
                segments = as_path.replace('[', '').replace(']', '').replace(',', '').split()
                if segments and segments[0] == str(from_as):
                    received_from_src = True
                    break

        # --- Step 2: Determine if best-path goes through a third AS ---
        best_path_via_third_as = False
        if not received_from_src and not df.empty:
            segments = best_as_path.replace('[', '').replace(']', '').replace(',', '').split()
            if segments and segments[0] != str(from_as):
                best_path_via_third_as = True

        # --- Step 3: Sender-side verification (fallback) ---
        ebgp_session_up = self._check_ebgp_session_exists(
            from_borders_lower, to_borders_lower
        )
        sender_has_route = self._sender_has_prefix(from_borders_lower, prefix)

        if action == "permit":
            if received_from_src:
                return VerifierResult(
                    property_id=prop.id,
                    status=VerificationStatus.PASS,
                    resolved_prefixes=resolved_prefixes,
                    query_details={"query": "bgp_rib", "action": "permit", "prefix": prefix,
                                   "from_as": from_as, "to_as": to_as,
                                   "method": "receiver_side",
                                   "result": "prefix_received_at_to_as"}
                )
            if best_path_via_third_as and sender_has_route and ebgp_session_up:
                return VerifierResult(
                    property_id=prop.id,
                    status=VerificationStatus.PASS,
                    resolved_prefixes=resolved_prefixes,
                    query_details={"query": "sender_side", "action": "permit", "prefix": prefix,
                                   "from_as": from_as, "to_as": to_as,
                                   "method": "sender_side",
                                   "best_path_as_path": best_as_path,
                                   "sender_has_route": True, "ebgp_session_up": True,
                                   "result": "sender_has_route_and_session_up"}
                )
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.FAIL,
                counterexample=CounterExample(
                    description=f"Prefix {prefix} NOT received at AS{to_as} from AS{from_as} (should be permitted)",
                    details={"from_as": from_as, "to_as": to_as, "prefix": prefix,
                             "sender_has_route": sender_has_route, "ebgp_session_up": ebgp_session_up}
                ),
                blame_nodes=list(from_borders),
                repair_hint=f"Check export policy on AS{from_as} border nodes or route propagation",
                resolved_prefixes=resolved_prefixes
            )

        else:  # action == "deny"
            if received_from_src:
                return VerifierResult(
                    property_id=prop.id,
                    status=VerificationStatus.FAIL,
                    counterexample=CounterExample(
                        description=f"Prefix {prefix} received at AS{to_as} from AS{from_as} (should be denied)",
                        details={"routes": df.to_dict('records')}
                    ),
                    blame_nodes=list(from_borders),
                    repair_hint=f"Add export filter on AS{from_as} border nodes to deny {prefix} to AS{to_as}",
                    resolved_prefixes=resolved_prefixes
                )
            if best_path_via_third_as:
                return VerifierResult(
                    property_id=prop.id,
                    status=VerificationStatus.PASS,
                    resolved_prefixes=resolved_prefixes,
                    query_details={"query": "bgp_rib", "action": "deny", "prefix": prefix,
                                   "from_as": from_as, "to_as": to_as,
                                   "method": "indirect_path_not_violation",
                                   "best_path_as_path": best_as_path,
                                   "result": (
                                       f"Prefix exists at AS{to_as} but via indirect path "
                                       f"(AS-path: {best_as_path}), not directly from AS{from_as}. "
                                       f"Export constraint only governs direct AS{from_as}→AS{to_as} export."
                                   )}
                )

            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.PASS,
                resolved_prefixes=resolved_prefixes,
                query_details={"query": "bgp_rib", "action": "deny", "prefix": prefix,
                               "from_as": from_as, "to_as": to_as,
                               "method": "receiver_side",
                               "result": "prefix_not_received_at_to_as"}
            )

    def _verify_no_transit(
        self,
        prop: PropertyIR,
        topo_ctx: TopologyContext,
        resolved_prefixes: Dict[str, List[str]]
    ) -> VerifierResult:
        """Verify no_transit: traceroute from src_as to dst_as prefixes, check if forbidden_as is in hop sequence."""
        src_as = prop.scope.get("src_as")
        dst_as = prop.scope.get("dst_as")
        forbidden_as = prop.scope.get("forbidden_as")
        prefixes = resolved_prefixes.get("prefixes", [])

        if not prefixes:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.ERROR,
                error_message="Failed to resolve prefixes",
                resolved_prefixes=resolved_prefixes
            )

        src_borders = self._get_as_borders(topo_ctx, src_as)
        if not src_borders:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.ERROR,
                error_message=f"No border nodes for AS{src_as}",
                resolved_prefixes=resolved_prefixes
            )

        forbidden_borders = set([b.lower() for b in self._get_as_borders(topo_ctx, forbidden_as)])

        violations = []
        failed_traces = []
        successful_traces = 0

        for src_node in [b.lower() for b in src_borders]:
            for prefix in prefixes:
                dst_ip = prefix.split('/')[0]

                success, traces, error = self.bf.query_traceroute(src_node, dst_ip)

                if not success:
                    failed_traces.append({
                        "src_node": src_node,
                        "prefix": prefix,
                        "error": error
                    })
                    continue

                for trace in traces:
                    successful_traces += 1
                    hops = trace.get("hops", [])
                    hops_lower = [h.lower() if isinstance(h, str) else str(h).lower() for h in hops]
                    forbidden_hit = [h for h in hops_lower if h in forbidden_borders]

                    if forbidden_hit:
                        violations.append({
                            "prefix": prefix,
                            "src_node": src_node,
                            "hops": hops,
                            "forbidden_nodes": forbidden_hit
                        })

        if successful_traces == 0 and failed_traces:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.ERROR,
                error_message=f"All traceroute queries failed ({len(failed_traces)} failures). Cannot verify no_transit.",
                resolved_prefixes=resolved_prefixes,
                query_details={"failed_traces": failed_traces[:5]}
            )

        if violations:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.FAIL,
                counterexample=CounterExample(
                    description=f"AS{forbidden_as} transits traffic from AS{src_as} to AS{dst_as}",
                    details={"violations": violations}
                ),
                blame_nodes=list(forbidden_borders),
                repair_hint=(
                    f"On AS{forbidden_as} borders: deny import of prefixes destined for AS{dst_as}, "
                    f"or on AS{src_as} borders: filter export to avoid AS{forbidden_as}"
                ),
                resolved_prefixes=resolved_prefixes
            )
        else:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.PASS,
                resolved_prefixes=resolved_prefixes,
                query_details={
                    "prefixes_tested": len(prefixes),
                    "successful_traces": successful_traces,
                    "failed_traces": len(failed_traces)
                }
            )

    def _verify_path_preference(
        self,
        prop: PropertyIR,
        topo_ctx: TopologyContext,
        resolved_prefixes: Dict[str, List[str]]
    ) -> VerifierResult:
        """Verify path_preference: prefer_egress/over_egress are LOCAL egress routers."""
        at_node = self._normalize_node_name(prop.scope.get("at"))
        prefer_egress = prop.predicate.get("prefer_egress")
        over_egress = prop.predicate.get("over_egress")
        prefixes = resolved_prefixes.get("prefix", [])

        if not prefixes:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.ERROR,
                error_message="Failed to resolve prefix",
                resolved_prefixes=resolved_prefixes
            )

        prefix = prefixes[0]

        success, route_info, error = self.bf.query_best_route(at_node, prefix, rib="bgp")

        if not success:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.ERROR,
                error_message=f"Batfish query failed: {error}",
                resolved_prefixes=resolved_prefixes
            )

        if not route_info:
            hint, blame, extra = self._route_not_found_context(prefix, at_node, topo_ctx)
            details = {"node": at_node, "prefix": prefix, **extra}
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.FAIL,
                counterexample=CounterExample(
                    description=f"No route to {prefix} at {at_node}",
                    details=details
                ),
                blame_nodes=blame or [at_node],
                repair_hint=hint or f"Check route propagation to {at_node}",
                resolved_prefixes=resolved_prefixes
            )

        next_hop_ip = route_info.get("next_hop_ip")

        next_hop_device = topo_ctx.ip_to_node.get(next_hop_ip)
        if not next_hop_device:
            for node, lo in topo_ctx.node_loopback.items():
                if lo.split('/')[0] == next_hop_ip:
                    next_hop_device = node
                    break

        def get_ebgp_neighbors(local_router: str) -> set:
            neighbors = set()
            local_lower = local_router.lower()
            for edge_key, pair in topo_ctx.as_edge_assignments.items():
                if len(pair) >= 2:
                    if pair[0].lower() == local_lower:
                        neighbors.add(pair[1].lower())
                    elif pair[1].lower() == local_lower:
                        neighbors.add(pair[0].lower())
            return neighbors

        prefer_neighbors = get_ebgp_neighbors(prefer_egress) if prefer_egress else set()
        over_neighbors = get_ebgp_neighbors(over_egress) if over_egress else set()

        next_hop_lower = next_hop_device.lower() if next_hop_device else "unknown"
        prefer_egress_lower = prefer_egress.lower() if prefer_egress else ""
        over_egress_lower = over_egress.lower() if over_egress else ""

        if next_hop_lower == prefer_egress_lower or next_hop_lower in prefer_neighbors:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.PASS,
                resolved_prefixes=resolved_prefixes,
                query_details={
                    "egress_router": prefer_egress,
                    "next_hop_device": next_hop_device,
                    "next_hop_ip": next_hop_ip
                }
            )

        if next_hop_lower == over_egress_lower or next_hop_lower in over_neighbors:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.FAIL,
                counterexample=CounterExample(
                    description=(
                        f"At {at_node}, traffic to {prefix} exits via {over_egress} "
                        f"(next-hop: {next_hop_device}) instead of preferred {prefer_egress}"
                    ),
                    details={
                        "preferred_egress": prefer_egress,
                        "actual_egress": over_egress,
                        "next_hop_device": next_hop_device,
                        "next_hop_ip": next_hop_ip,
                        "route": route_info
                    }
                ),
                blame_nodes=[at_node.lower(), prefer_egress.lower() if prefer_egress else at_node.lower()],
                repair_hint=(
                    f"On {at_node}: set higher local-pref for routes from {prefer_egress}'s eBGP neighbor, "
                    f"or lower local-pref for routes from {over_egress}'s neighbor"
                ),
                resolved_prefixes=resolved_prefixes
            )

        return VerifierResult(
            property_id=prop.id,
            status=VerificationStatus.FAIL,
            counterexample=CounterExample(
                description=(
                    f"At {at_node}, traffic to {prefix} uses unexpected next-hop {next_hop_device} "
                    f"(expected via {prefer_egress})"
                ),
                details={
                    "preferred_egress": prefer_egress,
                    "over_egress": over_egress,
                    "next_hop_device": next_hop_device,
                    "next_hop_ip": next_hop_ip,
                    "prefer_neighbors": list(prefer_neighbors),
                    "over_neighbors": list(over_neighbors),
                    "route": route_info
                }
            ),
            blame_nodes=[at_node.lower(), prefer_egress.lower() if prefer_egress else at_node.lower()],
            repair_hint=(
                f"Verify {prefer_egress} has eBGP connectivity and configure local-pref on {at_node}"
            ),
            resolved_prefixes=resolved_prefixes
        )

    def _verify_isolation(
        self,
        prop: PropertyIR,
        topo_ctx: TopologyContext,
        resolved_prefixes: Dict[str, List[str]]
    ) -> VerifierResult:
        """Verify isolation: node at 'at' should NOT have route to prefix"""
        at_node = self._normalize_node_name(prop.scope.get("at"))

        prefixes = resolved_prefixes.get("prefix", [])
        if not prefixes:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.ERROR,
                error_message="Failed to resolve prefix for isolation check",
                resolved_prefixes=resolved_prefixes
            )

        prefix = prefixes[0]
        success, df, error = self.bf.query_routes(
            nodes=at_node, network=prefix, rib="bgp"
        )

        if not success:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.ERROR,
                error_message=f"Batfish query failed: {error}",
                resolved_prefixes=resolved_prefixes
            )

        route_exists = not df.empty

        if prop.expect:  # expect isolation = expect route absent
            if not route_exists:
                return VerifierResult(
                    property_id=prop.id,
                    status=VerificationStatus.PASS,
                    resolved_prefixes=resolved_prefixes,
                    query_details={"query": "routes", "node": at_node, "prefix": prefix,
                                   "rib": "bgp", "result": "route_absent_as_expected"}
                )
            else:
                route_details = df.to_dict('records')[0] if not df.empty else {}
                next_hop = route_details.get('Next_Hop_IP', 'unknown')
                as_path = str(route_details.get('AS_Path', ''))

                origin_as = None
                for as_num, roles in topo_ctx.external_prefixes.items():
                    for role, cidr in roles.items():
                        if cidr == prefix:
                            origin_as = as_num
                            break
                    if origin_as:
                        break

                blame = [at_node]
                if origin_as:
                    origin_borders = self._get_as_borders(topo_ctx, origin_as)
                    blame.extend([b.lower() for b in origin_borders])

                hint = f"Prefix {prefix} should be blocked. "
                if origin_as:
                    hint += f"Options: 1) Don't originate {prefix} at AS{origin_as}, 2) Filter at {at_node} inbound"
                else:
                    hint += f"Add inbound filter at {at_node} to deny {prefix}"

                return VerifierResult(
                    property_id=prop.id,
                    status=VerificationStatus.FAIL,
                    counterexample=CounterExample(
                        description=f"Prefix {prefix} should be isolated but found at {at_node}",
                        details={
                            "node": at_node,
                            "prefix": prefix,
                            "next_hop": next_hop,
                            "as_path": as_path,
                            "origin_as": origin_as
                        }
                    ),
                    blame_nodes=list(dict.fromkeys(blame)),
                    repair_hint=hint,
                    resolved_prefixes=resolved_prefixes
                )
        else:  # expect NOT isolated = route should exist
            if route_exists:
                return VerifierResult(
                    property_id=prop.id,
                    status=VerificationStatus.PASS,
                    resolved_prefixes=resolved_prefixes,
                    query_details={"query": "routes", "node": at_node, "prefix": prefix,
                                   "rib": "bgp", "result": "route_present_as_expected",
                                   "num_routes": len(df)}
                )
            else:
                hint, blame, extra = self._route_not_found_context(prefix, at_node, topo_ctx)
                details = {"node": at_node, "prefix": prefix, **extra}
                return VerifierResult(
                    property_id=prop.id,
                    status=VerificationStatus.FAIL,
                    counterexample=CounterExample(
                        description=f"Prefix {prefix} not found at {at_node} but expected",
                        details=details
                    ),
                    blame_nodes=blame or [at_node],
                    repair_hint=hint or f"Check route propagation for {prefix} to {at_node}",
                    resolved_prefixes=resolved_prefixes
                )

    def _resolve_template_vars(self, value: str, prop: PropertyIR, topo_ctx: TopologyContext) -> str:
        """Resolve {src_as} etc. from scope/node context."""
        if "{src_as}" not in value:
            return value
        at_node = prop.scope.get("at", "")
        parts = at_node.replace("AS", "").split("_")
        src_as = parts[0] if parts else ""
        return value.replace("{src_as}", src_as)

    def _verify_route_aggregation(
        self,
        prop: PropertyIR,
        topo_ctx: TopologyContext,
        resolved_prefixes: Dict[str, List[str]]
    ) -> VerifierResult:
        """Verify route_aggregation: aggregate route exists and components are suppressed."""
        at_node = self._normalize_node_name(prop.scope.get("at"))
        aggregate = prop.predicate.get("aggregate")
        if aggregate:
            aggregate = self._resolve_template_vars(aggregate, prop, topo_ctx)
        suppress_components = prop.predicate.get("suppress_components", True)

        components = resolved_prefixes.get("components", [])
        if not components:
            raw_components = prop.predicate.get("components", [])
            for comp in raw_components:
                if isinstance(comp, dict) and comp.get("type") == "external_role":
                    as_num = self._resolve_template_vars(str(comp.get("as_num", "")), prop, topo_ctx)
                    role = comp.get("role", "")
                    ext_prefs = topo_ctx.external_prefixes.get(as_num) or topo_ctx.external_prefixes.get(int(as_num) if as_num.isdigit() else as_num, {})
                    cidr = ext_prefs.get(role)
                    if cidr:
                        components.append(cidr)

        if not aggregate:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.ERROR,
                error_message="No aggregate prefix specified",
                resolved_prefixes=resolved_prefixes
            )

        success, df_agg, error = self.bf.query_routes(
            nodes=at_node,
            network=aggregate,
            rib="bgp"
        )

        if not success:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.ERROR,
                error_message=f"Batfish query failed: {error}",
                resolved_prefixes=resolved_prefixes
            )

        if df_agg.empty:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.FAIL,
                counterexample=CounterExample(
                    description=f"Aggregate route {aggregate} not found at {at_node}",
                    details={"node": at_node, "aggregate": aggregate}
                ),
                blame_nodes=[at_node],
                repair_hint=f"Configure aggregate-address {aggregate} in BGP on {at_node}",
                resolved_prefixes=resolved_prefixes
            )

        if suppress_components and components:
            at_as = topo_ctx.node_to_as.get(at_node.upper()) or topo_ctx.node_to_as.get(at_node)

            check_node = None
            same_as_nodes = [
                n for n in topo_ctx.nodes
                if (topo_ctx.node_to_as.get(n) == at_as or topo_ctx.node_to_as.get(n.upper()) == at_as)
                and n.lower() != at_node
            ]
            for peer in same_as_nodes:
                check_node = peer.lower()
                break

            if not check_node:
                as_borders = self._get_as_borders(topo_ctx, at_as)
                for border in as_borders:
                    border_lower = border.lower()
                    if border_lower != at_node:
                        check_node = border_lower
                        break

            if not check_node:
                return VerifierResult(
                    property_id=prop.id,
                    status=VerificationStatus.ERROR,
                    error_message=f"No iBGP/eBGP peer found for {at_node} to verify component suppression",
                    resolved_prefixes=resolved_prefixes
                )

            violations = []
            for component in components:
                success, df_comp, error = self.bf.query_routes(
                    nodes=check_node,
                    network=component,
                    rib="bgp"
                )
                if success and not df_comp.empty:
                    for _, route in df_comp.iterrows():
                        nh = route.get('Next_Hop_IP', '')
                        at_node_upper = at_node.upper()
                        at_node_ips = set(
                            ip for ip, node in topo_ctx.ip_to_node.items()
                            if node == at_node_upper or node == at_node
                        )
                        at_loopback = topo_ctx.node_loopback.get(at_node_upper, '').split('/')[0]
                        if at_loopback:
                            at_node_ips.add(at_loopback)

                        if nh in at_node_ips:
                            violations.append(component)
                            break

            if violations:
                return VerifierResult(
                    property_id=prop.id,
                    status=VerificationStatus.FAIL,
                    counterexample=CounterExample(
                        description=f"Component routes leaked from {at_node} to {check_node}",
                        details={
                            "unsuppressed_components": violations,
                            "check_node": check_node
                        }
                    ),
                    blame_nodes=[at_node],
                    repair_hint=f"On {at_node}: add 'summary-only' to aggregate-address {aggregate} configuration",
                    resolved_prefixes=resolved_prefixes
                )

        return VerifierResult(
            property_id=prop.id,
            status=VerificationStatus.PASS,
            resolved_prefixes=resolved_prefixes,
            query_details={
                "aggregate": aggregate,
                "components_suppressed": suppress_components
            }
        )

    def _verify_as_path_prepend(
        self,
        prop: PropertyIR,
        topo_ctx: TopologyContext,
        resolved_prefixes: Dict[str, List[str]]
    ) -> VerifierResult:
        """Verify as_path_prepend: check AS path contains prepended AS numbers."""
        from_as = prop.scope.get("from_as")
        to_as = prop.scope.get("to_as")
        prepend_count = prop.predicate.get("prepend_count", 1)
        prefixes = resolved_prefixes.get("prefix", [])

        if not prefixes:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.ERROR,
                error_message="Failed to resolve prefix",
                resolved_prefixes=resolved_prefixes
            )

        prefix = prefixes[0]

        to_borders = self._get_as_borders(topo_ctx, to_as)
        if not to_borders:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.ERROR,
                error_message=f"No border nodes for AS{to_as}",
                resolved_prefixes=resolved_prefixes
            )

        to_pattern = f"/({('|'.join([b.lower() for b in to_borders]))})/".replace('_', '_')
        success, df, error = self.bf.query_routes(
            nodes=to_pattern,
            network=prefix,
            rib="bgp"
        )

        if not success:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.ERROR,
                error_message=f"Batfish query failed: {error}",
                resolved_prefixes=resolved_prefixes
            )

        if df.empty:
            hint, blame, extra = self._route_not_found_context(prefix, to_borders[0].lower(), topo_ctx)
            if hint:
                hint = hint.replace("Check: 1)", f"(needed for as_path_prepend from AS{from_as} to AS{to_as}) Check: 1)")
            else:
                from_borders = self._get_as_borders(topo_ctx, from_as)
                hint = (
                    f"Prefix {prefix} not found at AS{to_as}. "
                    f"Check: 1) prefix originated in AS{from_as}, "
                    f"2) eBGP sessions between AS{from_as} borders {[b.lower() for b in from_borders]} and AS{to_as} borders {[b.lower() for b in to_borders]}, "
                    f"3) next-hop-self on AS{to_as} border routers"
                )
                blame = [b.lower() for b in (self._get_as_borders(topo_ctx, from_as) + to_borders)]
            details = {"prefix": prefix, "from_as": from_as, "to_as": to_as, **extra}
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.FAIL,
                counterexample=CounterExample(
                    description=f"Route {prefix} not found at AS{to_as}",
                    details=details
                ),
                blame_nodes=blame or to_borders,
                repair_hint=hint,
                resolved_prefixes=resolved_prefixes
            )

        # --- Scan all returned routes for AS path analysis ---
        best_as_path_str = ""
        best_from_as_count = 0
        prepend_applied = False

        for _, route in df.iterrows():
            as_path_raw = str(route.get('AS_Path', ''))
            cleaned = as_path_raw.replace('[', '').replace(']', '').replace(',', '').strip()
            as_path_segments = cleaned.split()
            as_path_str = cleaned

            if not as_path_segments:
                continue

            consecutive_count = 0
            for seg in as_path_segments:
                if seg == str(from_as):
                    consecutive_count += 1
                else:
                    break

            if consecutive_count > best_from_as_count or (consecutive_count == best_from_as_count and not best_as_path_str):
                best_from_as_count = consecutive_count
                best_as_path_str = as_path_str

            if consecutive_count >= prepend_count + 1:
                prepend_applied = True

        from_borders = [b.lower() for b in self._get_as_borders(topo_ctx, from_as)]

        # --- Routing-effect verification ---
        alt_peer_ases = set()
        for edge in (topo_ctx.as_edges or []):
            e0, e1 = int(edge[0]), int(edge[1])
            if e0 == int(to_as) and e1 != int(from_as):
                alt_peer_ases.add(e1)
            elif e1 == int(to_as) and e0 != int(from_as):
                alt_peer_ases.add(e0)

        if alt_peer_ases:
            reachable = self._reachable_ases_excluding_edge(
                topo_ctx.as_edges, int(from_as), int(to_as)
            )
            alt_peer_ases = alt_peer_ases & reachable

        best_starts_with_from = (
            best_as_path_str and best_as_path_str.split()[0] == str(from_as)
        )
        from_as_in_path = str(from_as) in best_as_path_str.split()
        best_path_via_third_as = best_as_path_str and not best_starts_with_from

        if prepend_applied and best_starts_with_from and alt_peer_ases:
            prepend_path_len = prepend_count + 1
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.FAIL,
                counterexample=CounterExample(
                    description=(
                        f"Prepend applied (AS path '{best_as_path_str}') but AS{to_as} "
                        f"still selects the direct path from AS{from_as}. "
                        f"Alternative path via {['AS'+str(a) for a in alt_peer_ases]} "
                        f"should be shorter (len ~2) than the prepended path (len {prepend_path_len}), "
                        f"but it is not reaching AS{to_as} or not being selected."
                    ),
                    details={
                        "as_path": best_as_path_str,
                        "prepend_applied": True,
                        "prepend_path_length": prepend_path_len,
                        "alternative_peer_ases": sorted(alt_peer_ases),
                    }
                ),
                blame_nodes=from_borders,
                repair_hint=(
                    f"Prepend is configured correctly on AS{from_as}, but the alternative "
                    f"path via {['AS'+str(a) for a in sorted(alt_peer_ases)]} is not reaching AS{to_as}. "
                    f"Check: 1) prefix {prefix} is propagating through the transit AS, "
                    f"2) border routers in the transit AS have 'next-hop-self' for iBGP peers, "
                    f"3) eBGP sessions between transit AS and AS{to_as} are UP."
                ),
                resolved_prefixes=resolved_prefixes
            )

        if prepend_applied and not alt_peer_ases:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.PASS,
                resolved_prefixes=resolved_prefixes,
                query_details={
                    "as_path": best_as_path_str,
                    "consecutive_from_as": best_from_as_count,
                    "prepend_count": best_from_as_count - 1,
                    "method": "direct",
                    "note": "No alternative peer AS for routing-effect verification"
                }
            )

        if prepend_applied and best_path_via_third_as:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.PASS,
                resolved_prefixes=resolved_prefixes,
                query_details={
                    "as_path": best_as_path_str,
                    "best_path_length": len(best_as_path_str.split()),
                    "prepend_path_length": prepend_count + 1,
                    "method": "routing_effect",
                    "reason": (
                        f"Best path '{best_as_path_str}' goes through third AS, "
                        f"avoiding the prepended direct path from AS{from_as}. "
                        f"Prepend routing effect confirmed."
                    )
                }
            )

        # --- Indirect check ---
        if from_as_in_path and best_path_via_third_as:
            ebgp_exists = self._check_ebgp_session_exists(from_borders, [b.lower() for b in to_borders])
            if ebgp_exists:
                best_path_len = len(best_as_path_str.split())
                expected_prepend_path_len = prepend_count + 1
                if best_path_len <= expected_prepend_path_len:
                    return VerifierResult(
                        property_id=prop.id,
                        status=VerificationStatus.PASS,
                        resolved_prefixes=resolved_prefixes,
                        query_details={
                            "as_path": best_as_path_str,
                            "best_path_length": best_path_len,
                            "expected_prepend_path_length": expected_prepend_path_len,
                            "method": "indirect",
                            "reason": (
                                f"Best path '{best_as_path_str}' (len={best_path_len}) goes through "
                                f"third AS. Direct prepended path would be len={expected_prepend_path_len}. "
                                f"eBGP session between AS{from_as} and AS{to_as} is up. "
                                f"Path shift confirms prepend is effective."
                            )
                        }
                    )

        # All checks failed — genuine failure
        if best_from_as_count == 0:
            hint = (
                f"AS{from_as} not found at start of AS path. "
                f"Verify prefix is originated by AS{from_as} and prepend is configured on export to AS{to_as}"
            )
        elif best_from_as_count == 1:
            hint = (
                f"AS{from_as} appears only once (no prepending). "
                f"Configure route-map on AS{from_as} border with 'set as-path prepend {' '.join([str(from_as)] * prepend_count)}'"
            )
        else:
            hint = (
                f"AS{from_as} prepended {best_from_as_count - 1} times, expected {prepend_count}. "
                f"Adjust prepend count in route-map"
            )

        return VerifierResult(
            property_id=prop.id,
            status=VerificationStatus.FAIL,
            counterexample=CounterExample(
                description=f"AS{from_as} prepend count mismatch: found {best_from_as_count - 1}, expected {prepend_count}",
                details={
                    "as_path": best_as_path_str,
                    "consecutive_from_as": best_from_as_count,
                    "expected_prepend": prepend_count
                }
            ),
            blame_nodes=from_borders,
            repair_hint=hint,
            resolved_prefixes=resolved_prefixes
        )

    def _check_ebgp_session_exists(
        self,
        from_nodes: List[str],
        to_nodes: List[str]
    ) -> bool:
        """Check if at least one eBGP session exists between from_nodes and to_nodes."""
        from_set = set(n.lower() for n in from_nodes)
        to_set = set(n.lower() for n in to_nodes)

        for node in from_nodes:
            success, df, _ = self.bf.query_bgp_edges(nodes=node)
            if success and not df.empty:
                for _, row in df.iterrows():
                    remote = str(row.get('Remote_Node', '')).lower()
                    if remote in to_set:
                        return True

        for node in to_nodes:
            success, df, _ = self.bf.query_bgp_edges(nodes=node)
            if success and not df.empty:
                for _, row in df.iterrows():
                    remote = str(row.get('Remote_Node', '')).lower()
                    if remote in from_set:
                        return True

        return False

    @staticmethod
    def _lp_repair_hint(expected_lp: int, comparison: str, at_node: str) -> str:
        if comparison == "greater_than":
            suggested = expected_lp + 50
            return f"Configure route-map with 'set local-preference {suggested}' (must be > {expected_lp}) on {at_node}"
        elif comparison == "less_than":
            suggested = max(expected_lp - 50, 0)
            return f"Configure route-map with 'set local-preference {suggested}' (must be < {expected_lp}) on {at_node}"
        return f"Configure route-map with 'set local-preference {expected_lp}' on {at_node}"

    @staticmethod
    def _med_repair_hint(expected_med: int, comparison: str, at_node: str) -> str:
        if comparison == "greater_than":
            suggested = expected_med + 50
            return f"Configure route-map with 'set metric {suggested}' (must be > {expected_med}) on {at_node}"
        elif comparison == "less_than":
            suggested = max(expected_med - 50, 0)
            return f"Configure route-map with 'set metric {suggested}' (must be < {expected_med}) on {at_node}"
        return f"Configure route-map with 'set metric {expected_med}' on {at_node}"

    def _verify_local_preference(
        self,
        prop: PropertyIR,
        topo_ctx: TopologyContext,
        resolved_prefixes: Dict[str, List[str]]
    ) -> VerifierResult:
        """Verify local_preference — checks routing effect (egress selection)."""
        at_node = self._normalize_node_name(prop.scope.get("at"))
        prefer_egress = prop.predicate.get("prefer_egress")
        over_egress = prop.predicate.get("over_egress")
        prefixes = resolved_prefixes.get("prefix", [])

        if not prefixes:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.ERROR,
                error_message="Failed to resolve prefix",
                resolved_prefixes=resolved_prefixes
            )

        prefix = prefixes[0]

        success, route_info, error = self.bf.query_best_route(at_node, prefix, rib="bgp")

        if not success:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.ERROR,
                error_message=f"Batfish query failed: {error}",
                resolved_prefixes=resolved_prefixes
            )

        if not route_info:
            hint, blame, extra = self._route_not_found_context(prefix, at_node, topo_ctx)
            details = {"node": at_node, "prefix": prefix, **extra}
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.FAIL,
                counterexample=CounterExample(
                    description=f"Route {prefix} not found at {at_node}",
                    details=details
                ),
                blame_nodes=blame or [at_node],
                repair_hint=hint or f"Check route propagation to {at_node}",
                resolved_prefixes=resolved_prefixes
            )

        if prefer_egress and over_egress:
            next_hop_ip = route_info.get("next_hop_ip")
            next_hop_device = topo_ctx.ip_to_node.get(next_hop_ip)
            if not next_hop_device:
                for node, lo in topo_ctx.node_loopback.items():
                    if lo.split('/')[0] == next_hop_ip:
                        next_hop_device = node
                        break

            def get_ebgp_neighbors(local_router: str) -> set:
                neighbors = set()
                lr = local_router.lower()
                for edge_key, pair in topo_ctx.as_edge_assignments.items():
                    if len(pair) >= 2:
                        if pair[0].lower() == lr:
                            neighbors.add(pair[1].lower())
                        elif pair[1].lower() == lr:
                            neighbors.add(pair[0].lower())
                return neighbors

            prefer_neighbors = get_ebgp_neighbors(prefer_egress)
            over_neighbors = get_ebgp_neighbors(over_egress)
            nh_lower = next_hop_device.lower() if next_hop_device else "unknown"
            prefer_lower = prefer_egress.lower()
            over_lower = over_egress.lower()

            prefer_via = prop.predicate.get("prefer_via", "?")
            over_via = prop.predicate.get("over_via", "?")

            if nh_lower == prefer_lower or nh_lower in prefer_neighbors:
                return VerifierResult(
                    property_id=prop.id,
                    status=VerificationStatus.PASS,
                    resolved_prefixes=resolved_prefixes,
                    query_details={
                        "egress_router": prefer_egress,
                        "next_hop_device": next_hop_device,
                        "next_hop_ip": next_hop_ip,
                        "prefer_via": prefer_via,
                    }
                )

            if nh_lower == over_lower or nh_lower in over_neighbors:
                return VerifierResult(
                    property_id=prop.id,
                    status=VerificationStatus.FAIL,
                    counterexample=CounterExample(
                        description=(
                            f"At {at_node}, traffic to {prefix} goes via AS{over_via} "
                            f"({over_egress}) instead of preferred AS{prefer_via} ({prefer_egress})"
                        ),
                        details={
                            "preferred_egress": prefer_egress,
                            "actual_egress": over_egress,
                            "next_hop_device": next_hop_device,
                            "next_hop_ip": next_hop_ip,
                        }
                    ),
                    blame_nodes=[at_node.lower(), prefer_egress.lower()],
                    repair_hint=(
                        f"On {at_node}: set higher local-pref for routes via {prefer_egress} "
                        f"(toward AS{prefer_via}), or lower for routes via {over_egress}"
                    ),
                    resolved_prefixes=resolved_prefixes
                )

            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.FAIL,
                counterexample=CounterExample(
                    description=(
                        f"At {at_node}, traffic to {prefix} uses unexpected next-hop "
                        f"{next_hop_device} (expected via {prefer_egress})"
                    ),
                    details={
                        "preferred_egress": prefer_egress,
                        "over_egress": over_egress,
                        "next_hop_device": next_hop_device,
                        "next_hop_ip": next_hop_ip,
                        "prefer_neighbors": list(prefer_neighbors),
                        "over_neighbors": list(over_neighbors),
                    }
                ),
                blame_nodes=[at_node.lower(), prefer_egress.lower()],
                repair_hint=(
                    f"Verify {prefer_egress} has eBGP connectivity and configure "
                    f"higher local-pref on {at_node} for routes from AS{prefer_via}"
                ),
                resolved_prefixes=resolved_prefixes
            )

        # Fallback: legacy LP value check
        expected_lp = prop.predicate.get("local_pref", 200)
        comparison = prop.predicate.get("comparison", "greater_than")
        actual_lp = route_info.get("local_pref", 100)
        condition_met = (
            (comparison == "equal" and actual_lp == expected_lp) or
            (comparison == "greater_than" and actual_lp > expected_lp) or
            (comparison == "less_than" and actual_lp < expected_lp)
        )
        if condition_met:
            return VerifierResult(
                property_id=prop.id, status=VerificationStatus.PASS,
                resolved_prefixes=resolved_prefixes,
                query_details={"local_pref": actual_lp}
            )
        return VerifierResult(
            property_id=prop.id, status=VerificationStatus.FAIL,
            counterexample=CounterExample(
                description=f"LP mismatch at {at_node}: {actual_lp} vs {comparison} {expected_lp}",
                details={"expected": expected_lp, "actual": actual_lp}
            ),
            blame_nodes=[at_node],
            repair_hint=f"Set local-preference on {at_node} to satisfy {comparison} {expected_lp}",
            resolved_prefixes=resolved_prefixes
        )

    def _verify_med_manipulation(
        self,
        prop: PropertyIR,
        topo_ctx: TopologyContext,
        resolved_prefixes: Dict[str, List[str]]
    ) -> VerifierResult:
        """Verify med_manipulation — checks routing effect (ingress selection)."""
        at_node = self._normalize_node_name(prop.scope.get("at"))
        preferred_ingress = prop.predicate.get("preferred_ingress")
        other_ingress = prop.predicate.get("other_ingress")
        prefixes = resolved_prefixes.get("prefix", [])

        if not prefixes:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.ERROR,
                error_message="Failed to resolve prefix",
                resolved_prefixes=resolved_prefixes
            )

        prefix = prefixes[0]

        success, route_info, error = self.bf.query_best_route(at_node, prefix, rib="bgp")

        if not success:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.ERROR,
                error_message=f"Batfish query failed: {error}",
                resolved_prefixes=resolved_prefixes
            )

        if not route_info:
            hint, blame, extra = self._route_not_found_context(prefix, at_node, topo_ctx)
            details = {"node": at_node, "prefix": prefix, **extra}
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.FAIL,
                counterexample=CounterExample(
                    description=f"Route {prefix} not found at {at_node}",
                    details=details
                ),
                blame_nodes=blame or [at_node],
                repair_hint=hint or f"Check route propagation to {at_node}",
                resolved_prefixes=resolved_prefixes
            )

        if preferred_ingress and other_ingress:
            next_hop_ip = route_info.get("next_hop_ip")
            next_hop_device = topo_ctx.ip_to_node.get(next_hop_ip)
            if not next_hop_device:
                for node, lo in topo_ctx.node_loopback.items():
                    if lo.split('/')[0] == next_hop_ip:
                        next_hop_device = node
                        break

            def get_ebgp_neighbors(local_router: str) -> set:
                neighbors = set()
                lr = local_router.lower()
                for edge_key, pair in topo_ctx.as_edge_assignments.items():
                    if len(pair) >= 2:
                        if pair[0].lower() == lr:
                            neighbors.add(pair[1].lower())
                        elif pair[1].lower() == lr:
                            neighbors.add(pair[0].lower())
                return neighbors

            pref_neighbors = get_ebgp_neighbors(preferred_ingress)
            other_neighbors = get_ebgp_neighbors(other_ingress)
            nh_lower = next_hop_device.lower() if next_hop_device else "unknown"
            pref_lower = preferred_ingress.lower()
            other_lower = other_ingress.lower()

            from_as = prop.scope.get("from_as", "?")
            src_pref = prop.predicate.get("src_border_preferred", "?")
            src_other = prop.predicate.get("src_border_other", "?")

            if nh_lower == pref_lower or nh_lower in pref_neighbors:
                return VerifierResult(
                    property_id=prop.id,
                    status=VerificationStatus.PASS,
                    resolved_prefixes=resolved_prefixes,
                    query_details={
                        "ingress_router": preferred_ingress,
                        "next_hop_device": next_hop_device,
                        "next_hop_ip": next_hop_ip,
                    }
                )

            if nh_lower == other_lower or nh_lower in other_neighbors:
                return VerifierResult(
                    property_id=prop.id,
                    status=VerificationStatus.FAIL,
                    counterexample=CounterExample(
                        description=(
                            f"At {at_node}, traffic to {prefix} enters via {other_ingress} "
                            f"instead of preferred {preferred_ingress}"
                        ),
                        details={
                            "preferred_ingress": preferred_ingress,
                            "actual_ingress": other_ingress,
                            "next_hop_device": next_hop_device,
                            "next_hop_ip": next_hop_ip,
                        }
                    ),
                    blame_nodes=[src_pref, src_other],
                    repair_hint=(
                        f"On AS{from_as}: set lower MED on {src_pref}->{preferred_ingress} link, "
                        f"higher MED on {src_other}->{other_ingress} link"
                    ),
                    resolved_prefixes=resolved_prefixes
                )

            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.FAIL,
                counterexample=CounterExample(
                    description=(
                        f"At {at_node}, traffic to {prefix} uses unexpected next-hop "
                        f"{next_hop_device} (expected via {preferred_ingress})"
                    ),
                    details={
                        "preferred_ingress": preferred_ingress,
                        "other_ingress": other_ingress,
                        "next_hop_device": next_hop_device,
                        "next_hop_ip": next_hop_ip,
                    }
                ),
                blame_nodes=[src_pref, src_other],
                repair_hint=(
                    f"Verify eBGP connectivity and set MED on AS{from_as} to prefer "
                    f"{src_pref}->{preferred_ingress} path"
                ),
                resolved_prefixes=resolved_prefixes
            )

        # Fallback: legacy MED value check
        expected_med = prop.predicate.get("med", 100)
        comparison = prop.predicate.get("comparison", "equal")
        actual_med = route_info.get("metric", 0)
        condition_met = (
            (comparison == "equal" and actual_med == expected_med) or
            (comparison == "greater_than" and actual_med > expected_med) or
            (comparison == "less_than" and actual_med < expected_med)
        )
        if condition_met:
            return VerifierResult(
                property_id=prop.id, status=VerificationStatus.PASS,
                resolved_prefixes=resolved_prefixes,
                query_details={"med": actual_med}
            )
        return VerifierResult(
            property_id=prop.id, status=VerificationStatus.FAIL,
            counterexample=CounterExample(
                description=f"MED mismatch at {at_node}: {actual_med} vs {comparison} {expected_med}",
                details={"expected": expected_med, "actual": actual_med}
            ),
            blame_nodes=[at_node],
            repair_hint=f"Set MED on advertising router to satisfy {comparison} {expected_med}",
            resolved_prefixes=resolved_prefixes
        )

    def _verify_community_tagging(
        self,
        prop: PropertyIR,
        topo_ctx: TopologyContext,
        resolved_prefixes: Dict[str, List[str]]
    ) -> VerifierResult:
        """Verify community_tagging: check if BGP route has expected community tags."""
        at_node = self._normalize_node_name(prop.scope.get("at"))
        expected_community = prop.predicate.get("community")
        prefixes = resolved_prefixes.get("prefix", [])

        if not prefixes:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.ERROR,
                error_message="Failed to resolve prefix",
                resolved_prefixes=resolved_prefixes
            )

        prefix = prefixes[0]

        success, df, error = self.bf.query_routes(
            nodes=at_node,
            network=prefix,
            rib="bgp"
        )

        if not success:
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.ERROR,
                error_message=f"Batfish query failed: {error}",
                resolved_prefixes=resolved_prefixes
            )

        if df.empty:
            hint, blame, extra = self._route_not_found_context(prefix, at_node, topo_ctx)
            details = {"node": at_node, "prefix": prefix, **extra}
            return VerifierResult(
                property_id=prop.id,
                status=VerificationStatus.FAIL,
                counterexample=CounterExample(
                    description=f"Route {prefix} not found at {at_node}",
                    details=details
                ),
                blame_nodes=blame or [at_node],
                repair_hint=hint or f"Check route propagation to {at_node}",
                resolved_prefixes=resolved_prefixes
            )

        last_communities = []
        for _, route in df.iterrows():
            communities = route.get('Communities', [])
            if isinstance(communities, str):
                communities = [c.strip() for c in communities.split(',') if c.strip()]
            elif not isinstance(communities, list):
                communities = []
            last_communities = communities

            if expected_community in communities:
                return VerifierResult(
                    property_id=prop.id,
                    status=VerificationStatus.PASS,
                    resolved_prefixes=resolved_prefixes,
                    query_details={"communities": communities}
                )

        return VerifierResult(
            property_id=prop.id,
            status=VerificationStatus.FAIL,
            counterexample=CounterExample(
                description=f"Community {expected_community} not found at {at_node}",
                details={
                    "expected_community": expected_community,
                    "actual_communities": last_communities
                }
            ),
            blame_nodes=[at_node],
            repair_hint=f"Configure route-map with 'set community {expected_community}' on {at_node}",
            resolved_prefixes=resolved_prefixes
        )
