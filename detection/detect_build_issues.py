import pandas as pd
import joblib
from data_collection.build_time import get_build_data

# Load preprocessor and model for build-time detection
build_preprocessor = joblib.load('models/CVE-trivy_preprocessor.pkl')
build_model = joblib.load('models/CVE-trivy_model.pkl')

def detect_build_vulnerabilities(container_name):
    # Collect build data
    build_data = get_build_data(container_name)
    build_df = pd.DataFrame(build_data)
    build_df['combined_summary'] = build_df['Description']
    build_df.fillna({'CVSS': build_df['CVSS'].mean(), 'Severity': '', 'PkgName': ''}, inplace=True)
    
    # Preprocess build data
    build_data_processed = build_preprocessor.transform(build_df[['CVSS', 'combined_summary', 'Severity', 'PkgName']])
    
    # Make predictions
    build_predictions = build_model.predict(build_data_processed)
    return build_predictions

def main():
    container_name = input("Enter the Docker container name: ")
    build_vulnerabilities = detect_build_vulnerabilities(container_name)
    print(build_vulnerabilities)

if __name__ == "__main__":
    main()
