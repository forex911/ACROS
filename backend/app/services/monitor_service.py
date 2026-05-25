import psutil

def collect_behavior_data():

    process_count = len(psutil.pids())

    network_connections = len(psutil.net_connections())

    cpu_usage = psutil.cpu_percent()

    memory_usage = psutil.virtual_memory().percent

    return {
        "process_count": process_count,
        "network_connections": network_connections,
        "cpu_usage": cpu_usage,
        "memory_usage": memory_usage
    }