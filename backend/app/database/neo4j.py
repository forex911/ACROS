import logging
from neo4j import GraphDatabase, AsyncGraphDatabase
from app.core.config import settings

logger = logging.getLogger("neo4j_driver")

class Neo4jManager:
    def __init__(self):
        self.driver = None
        self.async_driver = None

    def init_driver(self):
        try:
            self.driver = GraphDatabase.driver(settings.NEO4J_URI, auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD))
            self.async_driver = AsyncGraphDatabase.driver(settings.NEO4J_URI, auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD))
            logger.info(f"Connected to Neo4j at {settings.NEO4J_URI}")
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")

    def close(self):
        if self.driver:
            self.driver.close()
        if self.async_driver:
            # Note: async_driver.close() must be awaited in async context
            pass

    async def aclose(self):
        if self.async_driver:
            await self.async_driver.close()

neo4j_manager = Neo4jManager()

def get_neo4j_session():
    if not neo4j_manager.driver:
        neo4j_manager.init_driver()
    return neo4j_manager.driver.session()

def get_neo4j_async_session():
    if not neo4j_manager.async_driver:
        neo4j_manager.init_driver()
    return neo4j_manager.async_driver.session()
