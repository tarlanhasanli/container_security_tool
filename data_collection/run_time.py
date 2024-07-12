import docker
import subprocess
import json
import time

def get_container_data(container_name, traffic_capture_duration=10):
    client = docker.from_env()
    
    try:
        container = client.containers.get(container_name)
    except docker.errors.NotFound:
        return f"Container '{container_name}' not found."

    # Fetch general runtime data
    container_info = container.attrs
    runtime_data = {
        'Id': container_info['Id'],
        'Name': container_info['Name'],
        'Image': container_info['Config']['Image'],
        'State': container_info['State'],
        'NetworkSettings': container_info['NetworkSettings']
    }

    # Fetch logs
    logs = container.logs(tail=2000).decode('utf-8')

    # Capture network traffic
    net_ns_path = f"/proc/{container.attrs['State']['Pid']}/net"
    tcpdump_command = [
        "sudo", "nsenter", "--net=" + net_ns_path, "tcpdump", "-c", "100", "-w", "-", "-i", "any"
    ]

    process = subprocess.Popen(tcpdump_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(traffic_capture_duration)
    process.terminate()

    stdout, stderr = process.communicate()

    if stderr:
        network_traffic = f"Error capturing network traffic: {stderr.decode('utf-8')}"
    else:
        network_traffic = stdout.decode('utf-8')

    # Combine all data into a single dictionary
    container_data = {
        'RuntimeData': runtime_data,
        'Logs': logs,
        'NetworkTraffic': network_traffic
    }

    return container_data

def main():
    container_name = input("Enter the Docker container name: ")
    duration = int(input("Enter the duration to capture network traffic (in seconds): "))
    
    container_data = get_container_data(container_name, duration)
    if isinstance(container_data, str):
        print(container_data)
    else:
        print("Container Data:")
        print(json.dumps(container_data, indent=4))

if __name__ == "__main__":
    main()
