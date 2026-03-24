"""
Batfish Adapter: Simplified Python client wrapper
- Uses pybatfish Session.q API
- Encapsulates common query patterns
- Unified error handling
"""
from typing import List, Dict, Any, Optional, Tuple
import pandas as pd
from pybatfish.client.session import Session


class BatfishAdapter:
    """Simplified Batfish client wrapper using Session.q API"""

    def __init__(self, host: str = "192.168.31.170", session_name: str = "taskgen"):
        self.host = host
        self.session_name = session_name
        self.session = None
        self.current_snapshot = None

    def connect(self) -> bool:
        """Establish connection to Batfish"""
        try:
            self.session = Session(host=self.host)
            return True
        except Exception as e:
            print(f"Failed to connect: {e}")
            return False

    def init_snapshot(self, snapshot_path: str, snapshot_name: str, overwrite: bool = True) -> bool:
        """Initialize a Batfish snapshot with retry logic."""
        import time

        if not self.session:
            if not self.connect():
                return False

        self.session.set_network(self.session_name)

        max_retries = 3
        for attempt in range(max_retries):
            try:
                if overwrite and attempt > 0:
                    try:
                        self.session.delete_snapshot(snapshot_name)
                    except Exception:
                        pass

                self.session.init_snapshot(
                    snapshot_path,
                    name=snapshot_name,
                    overwrite=overwrite
                )

                self.current_snapshot = snapshot_name
                return True

            except Exception as e:
                err_str = str(e)
                if "duplicate" in err_str.lower() and attempt < max_retries - 1:
                    print(f"Snapshot WorkID conflict (attempt {attempt + 1}/{max_retries}), retrying...")
                    time.sleep(1)
                    continue
                print(f"Failed to initialize snapshot: {e}")
                return False

    def query_routes(
        self,
        nodes: Optional[str] = None,
        network: Optional[str] = None,
        protocol: Optional[str] = None,
        rib: str = "main"
    ) -> Tuple[bool, pd.DataFrame, Optional[str]]:
        """Query routing table. Returns (success, dataframe, error_message)."""
        try:
            kwargs = {"rib": rib}
            if nodes is not None:
                kwargs["nodes"] = nodes
            if network is not None:
                kwargs["network"] = network
            q = self.session.q.routes(**kwargs)
            answer = q.answer(snapshot=self.current_snapshot)
            df = answer.frame()

            if protocol and not df.empty and 'Protocol' in df.columns:
                protocol_lower = protocol.lower()
                if protocol_lower == 'bgp':
                    df = df[df['Protocol'].str.lower().str.contains('bgp|local', case=False, na=False)]
                else:
                    df = df[df['Protocol'].str.lower() == protocol_lower]

            return True, df, None

        except Exception as e:
            return False, pd.DataFrame(), str(e)

    def query_bgp_edges(
        self,
        nodes: Optional[str] = None,
        remote_nodes: Optional[str] = None
    ) -> Tuple[bool, pd.DataFrame, Optional[str]]:
        """Query BGP session edges."""
        try:
            kwargs = {}
            if nodes is not None:
                kwargs["nodes"] = nodes
            if remote_nodes is not None:
                kwargs["remoteNodes"] = remote_nodes
            q = self.session.q.bgpEdges(**kwargs)
            answer = q.answer(snapshot=self.current_snapshot)
            df = answer.frame()
            return True, df, None
        except Exception as e:
            return False, pd.DataFrame(), str(e)

    def query_bgp_peer_config(
        self,
        nodes: Optional[str] = None
    ) -> Tuple[bool, pd.DataFrame, Optional[str]]:
        """Query BGP peer configuration (includes Export_Policy, Import_Policy columns)."""
        try:
            kwargs = {}
            if nodes is not None:
                kwargs["nodes"] = nodes
            q = self.session.q.bgpPeerConfiguration(**kwargs)
            answer = q.answer(snapshot=self.current_snapshot)
            df = answer.frame()
            return True, df, None
        except Exception as e:
            return False, pd.DataFrame(), str(e)

    def query_bgp_session_status(
        self,
        nodes: Optional[str] = None,
        status: Optional[str] = None
    ) -> Tuple[bool, pd.DataFrame, Optional[str]]:
        """Query BGP session status (established vs not)."""
        try:
            kwargs = {}
            if nodes is not None:
                kwargs["nodes"] = nodes
            if status is not None:
                kwargs["status"] = status
            q = self.session.q.bgpSessionStatus(**kwargs)
            answer = q.answer(snapshot=self.current_snapshot)
            df = answer.frame()
            return True, df, None
        except Exception as e:
            return False, pd.DataFrame(), str(e)

    def query_bgp_rib(
        self,
        nodes: Optional[str] = None,
        prefix: Optional[str] = None
    ) -> Tuple[bool, pd.DataFrame, Optional[str]]:
        """Query BGP RIB entries."""
        try:
            kwargs = {}
            if nodes:
                kwargs['nodes'] = nodes
            if prefix:
                kwargs['network'] = prefix

            q = self.session.q.bgpRib(**kwargs)
            answer = q.answer(snapshot=self.current_snapshot)
            df = answer.frame()
            return True, df, None
        except Exception as e:
            return False, pd.DataFrame(), str(e)

    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Check if string is a valid IPv4/IPv6 address."""
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except (ValueError, TypeError):
            return False

    def query_traceroute(
        self,
        src_node: str,
        dst_ip: str
    ) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
        """Query data-plane traceroute. Returns (success, trace_list, error_message)."""
        try:
            if not src_node or not isinstance(src_node, str):
                return False, [], f"Invalid startLocation: {src_node!r}"
            if not dst_ip or not isinstance(dst_ip, str):
                return False, [], f"Invalid dst_ip: {dst_ip!r}"
            if not self._is_valid_ip(dst_ip):
                return False, [], f"Invalid IP address format for dst_ip: {dst_ip!r}"
            q = self.session.q.traceroute(startLocation=str(src_node), headers={"dstIps": str(dst_ip)})
            answer = q.answer(snapshot=self.current_snapshot)
            df = answer.frame()

            if df.empty:
                return True, [], None

            traces = []
            for _, row in df.iterrows():
                trace_info = {
                    "flow": str(row.get("Flow", {})),
                    "traces": str(row.get("Traces", [])),
                    "disposition": self._extract_disposition(row),
                    "hops": self._extract_hops_from_row(row)
                }
                traces.append(trace_info)

            return True, traces, None

        except Exception as e:
            return False, [], str(e)

    def query_best_route(
        self,
        node: str,
        prefix: str,
        rib: str = "bgp"
    ) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
        """Query best route for a prefix at a node."""
        try:
            success, df, error = self.query_routes(
                nodes=node,
                network=prefix,
                rib=rib
            )

            if not success:
                return False, None, error

            if df.empty:
                return True, None, "No route found"

            best = df.iloc[0]
            def _safe(v):
                if v is None:
                    return None
                if isinstance(v, (int, float, bool, str)):
                    return v
                return str(v)
            def _str_or_none(v):
                if v is None:
                    return None
                s = str(v)
                if s in ("", "nan", "None", "AUTO/NONE(-1l)") or "NONE" in s.upper():
                    return None
                return s

            route_info = {
                "network": _str_or_none(best.get("Network")) or "",
                "node": _str_or_none(best.get("Node")) or "",
                "next_hop": _str_or_none(best.get("Next_Hop")) or "",
                "next_hop_ip": _str_or_none(best.get("Next_Hop_IP")),
                "protocol": _str_or_none(best.get("Protocol")) or "",
                "metric": _safe(best.get("Metric")),
            }

            return True, route_info, None

        except Exception as e:
            return False, None, str(e)

    def query_reachability(
        self,
        src_node: str,
        dst_ip: str,
        expected_disposition: str = "ACCEPTED"
    ) -> Tuple[bool, bool, Optional[str]]:
        """Check if dst_ip is reachable from src_node. Returns (query_success, is_reachable, error)."""
        try:
            success, traces, error = self.query_traceroute(src_node, dst_ip)

            if not success:
                return False, False, error

            if not traces:
                return True, False, "No traces found"

            accept_set = {expected_disposition.upper(), "DELIVERED"} if expected_disposition else {"ACCEPTED", "DELIVERED"}
            for trace in traces:
                disp = trace.get("disposition", "").upper()
                if disp in accept_set:
                    return True, True, None

            return True, False, "Not reachable"

        except Exception as e:
            return False, False, str(e)

    def get_snapshot_parse_status(self) -> Tuple[bool, Dict[str, Any]]:
        """Get snapshot parse status."""
        try:
            q = self.session.q.fileParseStatus()
            answer = q.answer(snapshot=self.current_snapshot)
            df = answer.frame()

            status = {
                "total_files": len(df),
                "parsed": [],
                "failed": [],
                "warnings": []
            }

            if not df.empty:
                if 'Status' in df.columns:
                    status["parsed"] = df[df['Status'] == 'PASSED']['File_Name'].tolist()
                    status["failed"] = df[df['Status'] == 'FAILED']['File_Name'].tolist()

            return True, status

        except Exception as e:
            return False, {"error": str(e)}

    def _extract_disposition(self, row: pd.Series) -> str:
        """Extract disposition from trace row"""
        traces = row.get("Traces", [])
        if traces and len(traces) > 0:
            trace = traces[0]
            if hasattr(trace, 'disposition'):
                return str(trace.disposition)
        return "UNKNOWN"

    def _extract_hops_from_row(self, row: pd.Series) -> List[str]:
        """Extract hop sequence from trace row"""
        hops = []
        traces = row.get("Traces", [])

        if not traces:
            return hops

        for trace in traces:
            if hasattr(trace, 'hops'):
                for hop in trace.hops:
                    if hasattr(hop, 'node'):
                        node_name = hop.node.hostname if hasattr(hop.node, 'hostname') else str(hop.node)
                        hops.append(node_name)

        return hops


def test_batfish_connection(host: str = "192.168.31.170") -> bool:
    """Test connection to Batfish server."""
    try:
        adapter = BatfishAdapter(host=host)
        if adapter.connect():
            adapter.session.set_network("connection_test")
            print(f"Successfully connected to Batfish at {host}")
            return True
        return False
    except Exception as e:
        print(f"Failed to connect to Batfish at {host}: {e}")
        return False
