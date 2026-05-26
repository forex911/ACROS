def extract_and_store_iocs(static_results, telemetry_events):
    # This combines static and dynamic findings to generate unique IOCs
    iocs = []
    seen = set()
    
    def add_ioc(ioc_type, value, source, confidence="Low"):
        if value and value not in seen:
            seen.add(value)
            iocs.append({
                "type": ioc_type,
                "value": value,
                "source": source,
                "confidence": confidence
            })

    # From Static
    if "strings" in static_results:
        for ip in static_results["strings"].get("ips", []):
            add_ioc("ip", ip, "Static Analysis (Strings)", "Low")
        for url in static_results["strings"].get("urls", []):
            add_ioc("url", url, "Static Analysis (Strings)", "Low")
        for dom in static_results["strings"].get("domains", []):
            add_ioc("domain", dom, "Static Analysis (Strings)", "Low")

    if "hash" in static_results:
        add_ioc("sha256", static_results["hash"].get("sha256"), "Static Analysis (Hash)", "High")
        add_ioc("md5", static_results["hash"].get("md5"), "Static Analysis (Hash)", "High")

    # From Runtime
    for event in telemetry_events:
        evt_type = event.get("type")
        data = event.get("data", {})
        
        if evt_type == "SOCKET_CONNECT" or evt_type == "NETWORK_CONNECT":
            add_ioc("ip", data.get("dest_ip"), "Runtime Telemetry", "High")
        elif evt_type == "HTTP_REQUEST":
            add_ioc("url", data.get("url"), "Runtime Telemetry", "High")
        elif evt_type == "DNS_QUERY":
            add_ioc("domain", data.get("query"), "Runtime Telemetry", "High")
        elif evt_type == "PROCESS_CREATE" or evt_type == "EXECUTION":
            cmdline = data.get("cmdline", "")
            if "powershell" in cmdline.lower() and "-enc" in cmdline.lower():
                add_ioc("command", "powershell -enc ...", "Runtime Telemetry", "Medium")
            
    return iocs
