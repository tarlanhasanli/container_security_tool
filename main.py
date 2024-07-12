from detection.detect_build_issues import detect_build_vulnerabilities
from detection.detect_runtime_issues import detect_runtime_anomalies

def main():
    container_name = 'your_container_name'
    
    # Detect build-time vulnerabilities
    build_issues = detect_build_vulnerabilities(container_name)
    print("Build Issues:", build_issues)

    # Detect runtime anomalies
    runtime_anomalies = detect_runtime_anomalies(container_name)
    print("Runtime Anomalies:", runtime_anomalies)

if __name__ == "__main__":
    main()
