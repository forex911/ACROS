"""
Graph Schema Stabilization Tests

Unit tests validate schema constants and Cypher query construction.
Integration test validates end-to-end graph traversal in a single Neo4j session.
"""
import pytest
import uuid
import re

from app.models.graph_schema import RelType, NodeLabel, ARTIFACT_RELS


# ============================================================================
# UNIT TESTS — Schema Constants (no Neo4j required)
# ============================================================================

class TestSchemaConstants:
    """Validates that graph_schema.py is complete and internally consistent."""

    def test_reltype_all_returns_all_constants(self):
        """RelType.all() must include every string attribute on the class."""
        all_rels = RelType.all()
        expected = {
            "ANALYZES", "SPAWNED_PROCESS", "SPAWNED", "CONNECTED_TO",
            "EXHIBITS_TECHNIQUE", "DROPPED", "DOWNLOADED", "CREATED",
            "EXTRACTED", "FOLLOWED_BY", "MATCHES_YARA", "RESOLVED",
            "QUERIED_DNS", "PRODUCED_IOC", "HAS_STAGE",
            "MODIFIED_REGISTRY", "INJECTED_INTO", "PERSISTED_VIA",
        }
        assert set(all_rels) == expected

    def test_artifact_rels_subset_of_reltype(self):
        """Every ARTIFACT_RELS entry must be a valid RelType constant."""
        all_rels = set(RelType.all())
        for rel in ARTIFACT_RELS:
            assert rel in all_rels, f"ARTIFACT_RELS contains '{rel}' not in RelType"

    def test_node_labels_present(self):
        """All expected node labels exist."""
        expected = ["FILE", "SANDBOX_JOB", "PROCESS", "IP_ADDRESS",
                    "YARA_RULE", "ATTACK_TECHNIQUE", "DOMAIN", "HASH",
                    "TIMELINE_STAGE", "REGISTRY_KEY", "PERSISTENCE_MECHANISM"]
        for attr in expected:
            assert hasattr(NodeLabel, attr), f"NodeLabel missing '{attr}'"

    def test_no_duplicate_relationship_values(self):
        """No two RelType constants should resolve to the same string."""
        all_rels = RelType.all()
        assert len(all_rels) == len(set(all_rels)), "Duplicate relationship values found"


class TestCypherQueryConstruction:
    """Validates that service code builds Cypher with schema constants, not hardcoded strings."""

    def _read_source(self, module_path: str) -> str:
        import importlib
        mod = importlib.import_module(module_path)
        import inspect
        return inspect.getsource(mod)

    def test_graph_ingester_uses_reltype_constants(self):
        """graph_ingester.py must reference RelType for every relationship."""
        source = self._read_source("app.services.graph_ingester")
        # Find all Cypher relationship patterns like -[:SOMETHING]->
        cypher_rels = re.findall(r'\[:\s*{?\s*(\w+)', source)
        # Filter out f-string variable interpolation placeholders
        hardcoded = [r for r in cypher_rels if r.isupper() and "RelType" not in r]
        # All uppercase rels in the Cypher should come from RelType.XXX via f-string
        # The actual f-string pattern is :{RelType.XXX} which produces :ANALYZES etc.
        # So we check the raw source for hardcoded patterns like -[:ANALYZES]->
        hardcoded_patterns = re.findall(r'\[:\s*(?!{)([A-Z_]+)\s*[\]{ ]', source)
        assert hardcoded_patterns == [], (
            f"graph_ingester.py has hardcoded relationship strings: {hardcoded_patterns}. "
            "Use RelType constants instead."
        )

    def test_threat_correlation_uses_reltype_constants(self):
        """threat_correlation.py must reference RelType for every relationship."""
        source = self._read_source("app.services.threat_correlation")
        hardcoded_patterns = re.findall(r'\[:\s*(?!{)([A-Z_]+)\s*[\]{ ]', source)
        assert hardcoded_patterns == [], (
            f"threat_correlation.py has hardcoded relationship strings: {hardcoded_patterns}. "
            "Use RelType constants instead."
        )

    def test_graph_routes_uses_reltype_constants(self):
        """graph.py API routes must reference RelType for every relationship."""
        source = self._read_source("app.api.routes.graph")
        hardcoded_patterns = re.findall(r'\[:\s*(?!{)([A-Z_]+)\s*[\]{ ]', source)
        # The artifact pipe syntax DROPPED|DOWNLOADED... is built dynamically from ARTIFACT_RELS
        # so we filter out that specific pattern
        assert hardcoded_patterns == [], (
            f"graph.py has hardcoded relationship strings: {hardcoded_patterns}. "
            "Use RelType constants instead."
        )

    def test_artifact_rels_join_produces_valid_cypher(self):
        """ARTIFACT_RELS should join into a valid Cypher pipe-delimited type filter."""
        joined = "|".join(ARTIFACT_RELS)
        assert "|" in joined
        for rel in ARTIFACT_RELS:
            assert rel in joined
        # Must not contain spaces or special chars
        assert re.match(r'^[A-Z_]+(\|[A-Z_]+)*$', joined), f"Invalid Cypher join: {joined}"


# ============================================================================
# INTEGRATION TEST — Single consolidated test (requires live Neo4j)
# ============================================================================

@pytest.mark.asyncio
async def test_full_graph_traversal_e2e():
    """
    End-to-end test: ingests a complete execution graph and validates
    every traversal path within a single async context to avoid
    Windows ProactorEventLoop socket issues.
    """
    from app.database.neo4j import get_neo4j_async_session
    from app.models.graph_schema import RelType

    job_id = f"test-schema-{uuid.uuid4()}"
    sha256 = f"deadbeef{uuid.uuid4().hex[:24]}"

    async with get_neo4j_async_session() as session:
        # --- WRITE PHASE ---

        # 1. Job -> File (ANALYZES)
        await session.run(f"""
            MERGE (f:File {{sha256: $sha256}})
            ON CREATE SET f.name = 'test.exe'
            MERGE (j:SandboxJob {{job_id: $job_id}})
            MERGE (j)-[:{RelType.ANALYZES}]->(f)
        """, sha256=sha256, job_id=job_id)

        # 2. Job -> Process (SPAWNED_PROCESS)
        await session.run(f"""
            MATCH (j:SandboxJob {{job_id: $job_id}})
            MERGE (p:Process {{pid: 1234, job_id: $job_id}})
            ON CREATE SET p.executable = 'test.exe', p.command = 'test.exe -a'
            MERGE (j)-[:{RelType.SPAWNED_PROCESS}]->(p)
        """, job_id=job_id)

        # 3. Parent -> Child Process (SPAWNED)
        await session.run(f"""
            MATCH (child:Process {{pid: 1234, job_id: $job_id}})
            MERGE (parent:Process {{pid: 1000, job_id: $job_id}})
            MERGE (parent)-[:{RelType.SPAWNED}]->(child)
        """, job_id=job_id)

        # 4. Process -> IP (CONNECTED_TO)
        await session.run(f"""
            MATCH (p:Process {{pid: 1234, job_id: $job_id}})
            MERGE (ip:IPAddress {{address: '8.8.8.8'}})
            MERGE (p)-[:{RelType.CONNECTED_TO} {{port: 443, protocol: 'TCP'}}]->(ip)
        """, job_id=job_id)

        # 5. Job -> AttackTechnique (EXHIBITS_TECHNIQUE)
        await session.run(f"""
            MATCH (j:SandboxJob {{job_id: $job_id}})
            MERGE (t:AttackTechnique {{technique_id: 'T1059'}})
            ON CREATE SET t.name = 'Command and Scripting Interpreter', t.tactic = 'Execution'
            MERGE (j)-[:{RelType.EXHIBITS_TECHNIQUE}]->(t)
        """, job_id=job_id)

        # 6. Timeline: HAS_STAGE + FOLLOWED_BY
        for stage in [1, 2]:
            await session.run(f"""
                MATCH (j:SandboxJob {{job_id: $job_id}})
                MERGE (s:TimelineStage {{job_id: $job_id, stage: $stage}})
                SET s.label = 'Stage ' + toString($stage)
                MERGE (j)-[:{RelType.HAS_STAGE}]->(s)
            """, job_id=job_id, stage=stage)

        await session.run(f"""
            MATCH (a:TimelineStage {{job_id: $job_id, stage: 1}})
            MATCH (b:TimelineStage {{job_id: $job_id, stage: 2}})
            MERGE (a)-[:{RelType.FOLLOWED_BY}]->(b)
        """, job_id=job_id)

        # --- READ / VERIFY PHASE ---

        # 1. ANALYZES
        res = await session.run(f"""
            MATCH (j:SandboxJob {{job_id: $job_id}})-[r:{RelType.ANALYZES}]->(f:File {{sha256: $sha256}})
            RETURN count(r) as c
        """, job_id=job_id, sha256=sha256)
        assert (await res.single())["c"] == 1, "ANALYZES relationship missing"

        # 2. SPAWNED_PROCESS
        res = await session.run(f"""
            MATCH (j:SandboxJob {{job_id: $job_id}})-[r:{RelType.SPAWNED_PROCESS}]->(p:Process {{pid: 1234}})
            RETURN count(r) as c
        """, job_id=job_id)
        assert (await res.single())["c"] == 1, "SPAWNED_PROCESS relationship missing"

        # 3. SPAWNED
        res = await session.run(f"""
            MATCH (parent:Process {{pid: 1000, job_id: $job_id}})-[r:{RelType.SPAWNED}]->(child:Process {{pid: 1234}})
            RETURN count(r) as c
        """, job_id=job_id)
        assert (await res.single())["c"] == 1, "SPAWNED relationship missing"

        # 4. CONNECTED_TO
        res = await session.run(f"""
            MATCH (p:Process {{pid: 1234, job_id: $job_id}})-[r:{RelType.CONNECTED_TO}]->(ip:IPAddress {{address: '8.8.8.8'}})
            RETURN r.port as port
        """, job_id=job_id)
        record = await res.single()
        assert record is not None, "CONNECTED_TO relationship missing"
        assert record["port"] == 443

        # 5. EXHIBITS_TECHNIQUE
        res = await session.run(f"""
            MATCH (j:SandboxJob {{job_id: $job_id}})-[r:{RelType.EXHIBITS_TECHNIQUE}]->(t:AttackTechnique {{technique_id: 'T1059'}})
            RETURN count(r) as c
        """, job_id=job_id)
        assert (await res.single())["c"] == 1, "EXHIBITS_TECHNIQUE relationship missing"

        # 6. HAS_STAGE + FOLLOWED_BY
        res = await session.run(f"""
            MATCH (j:SandboxJob {{job_id: $job_id}})-[:{RelType.HAS_STAGE}]->(s:TimelineStage)
            RETURN count(s) as c
        """, job_id=job_id)
        assert (await res.single())["c"] == 2, "HAS_STAGE chain incomplete"

        res = await session.run(f"""
            MATCH (a:TimelineStage {{job_id: $job_id, stage: 1}})-[r:{RelType.FOLLOWED_BY}]->(b:TimelineStage {{job_id: $job_id, stage: 2}})
            RETURN count(r) as c
        """, job_id=job_id)
        assert (await res.single())["c"] == 1, "FOLLOWED_BY relationship missing"

        # --- CLEANUP ---
        await session.run("""
            MATCH (n) WHERE n.job_id = $job_id DETACH DELETE n
        """, job_id=job_id)
        await session.run("""
            MATCH (ip:IPAddress {address: '8.8.8.8'}) WHERE NOT ()-[]->(ip) DELETE ip
        """)
        await session.run("""
            MATCH (t:AttackTechnique {technique_id: 'T1059'}) WHERE NOT ()-[]->(t) DELETE t
        """)
