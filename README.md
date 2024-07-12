# Docker Container Vulnerability Detection Tool
This project aims to enhance the security of Docker containers by leveraging machine learning models to detect build-time and runtime vulnerabilities, risks, and anomalies. The tool uses different models trained on various datasets to provide comprehensive security analysis.

## Overview
The objective of this project is to improve Docker container security by detecting vulnerabilities and anomalies during both build and runtime phases. The tool uses the following models and datasets:

- Build-Time Detection: RandomForest model trained on CVE and Trivy scan results.
- Runtime Detection:
    - RandomForest model trained on UNSW-NB15 dataset.
    - XGBoost model trained on CIC-IDS2017 dataset.
    - Autoencoder model trained on Bot-IoT dataset.

## Preprocessing
### UNSW-NB15 Dataset
The UNSW-NB15 dataset provides a mix of normal and malicious network traffic, essential for training models to distinguish between benign activities and potential threats. The preprocessing involves fitting LabelEncoders to categorical columns and scaling the numerical features.

### CIC-IDS2017 Dataset
The CIC-IDS2017 dataset includes a variety of attack scenarios that mirror threats targeting Docker containers. Preprocessing involves combining multiple CSV files, encoding categorical features, and scaling the data.

### Bot-IoT Dataset
The Bot-IoT dataset focuses on IoT network traffic. The preprocessing involves handling data in chunks due to its size, fitting LabelEncoders, and scaling the data. An autoencoder model is trained to detect anomalies based on reconstruction error.

## Data Collection
### Build Time Data Collection
The build_time.py script includes the get_build_data function which collects relevant build-time data such as package names, installed versions, severity, descriptions, and CVSS scores.

### Runtime Data Collection
The run_time.py script includes the get_container_data function which collects runtime data including RuntimeData, logs, and network traffic.

## Detection
### Build Time Detection
The detect_build_issues.py script uses the collected build data to detect vulnerabilities using the pre-trained RandomForest model. The collected data is preprocessed, and predictions are made to identify potential issues.

### Runtime Detection
The detect_runtime_issues.py script uses collected runtime data to detect anomalies. The script processes the data using appropriate label encoders and preprocessors before feeding it to the pre-trained models for predictions.

## Running Locally
### 1. Setup Environment:
Ensure you have Python 3.9 or higher installed. Create a virtual environment and install dependencies:

```Shell
pip install -r requirements.txt
```

### 2. Run the Tool:
Execute the main.py script to start the tool:

```Shell
python main.py
```