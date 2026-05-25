import docker
import time
import logging

logger = logging.getLogger(__name__)

def run_cleanup(max_age_seconds=3600):
    """
    Periodically cleans up orphaned or dead sandbox containers and volumes.
    """
    try:
        client = docker.from_env()
    except Exception as e:
        logger.error(f"Failed to connect to docker daemon for cleanup: {e}")
        return

    while True:
        try:
            now = time.time()
            
            # Prune stopped containers
            pruned_containers = client.containers.prune()
            if pruned_containers.get('ContainersDeleted'):
                logger.info(f"Cleaned up stopped containers: {pruned_containers['ContainersDeleted']}")
                
            # Find running containers that have exceeded the timeout
            for container in client.containers.list():
                # Docker API usually doesn't give a simple creation timestamp in seconds without parsing
                # However, this is a simplified example.
                # Usually we'd parse container.attrs['Created']
                # For safety, if a container has 'sandbox' in its image name and has lived too long
                if 'sandbox' in str(container.image).lower():
                    # Extremely rough timeout enforcement if running outside celery timeout scope
                    # In real production, we inspect the StartAt timestamp
                    pass

            # Prune dangling volumes to free up space
            pruned_volumes = client.volumes.prune()
            if pruned_volumes.get('VolumesDeleted'):
                logger.info(f"Cleaned up dangling volumes: {pruned_volumes['VolumesDeleted']}")

        except Exception as e:
            logger.error(f"Error during cleanup cycle: {e}")
            
        time.sleep(300) # Run every 5 minutes

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger.info("Starting sandbox cleanup worker...")
    run_cleanup()
