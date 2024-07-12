import json
import pandas as pd
import os
import joblib

from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

base_url = '' # Enter base url

# List of JSON files
json_files = [
    'trivy_output_httpd.json',
    'trivy_output_mysql.json',
    'trivy_output_nginx.json',
    'trivy_output_node.json',
    'trivy_output_openjdk.json',
    'trivy_output_postgres.json',
    'trivy_output_python.json'
]

def load_trivy_data(file_path):
    file_path_url = f"{base_url}/{file_path}"
    try:
        with open(file_path_url, encoding='utf-8') as file:
            trivy_data = json.load(file)
    except UnicodeDecodeError:
        with open(file_path_url, encoding='latin1') as file:
            trivy_data = json.load(file)
    vulnerabilities = trivy_data['Results'][0]['Vulnerabilities']
    return pd.DataFrame(vulnerabilities)

def load_and_combine_trivy_files():
    # Load and combine data from all JSON files
    trivy_dfs = [load_trivy_data(file) for file in json_files]
    trivy_combined_df = pd.concat(trivy_dfs, ignore_index=True)

    # Ensure the combined DataFrame has the relevant columns
    trivy_combined_df = trivy_combined_df[['VulnerabilityID', 'PkgName', 'InstalledVersion', 'Severity', 'Description']]
    return trivy_combined_df

def collect_trivy_cve_data():
    trivy_combined_df = load_and_combine_trivy_files()
    cve_df = pd.read_csv(f"{base_url}/cve.csv")

    # Merge CVE and Trivy data
    combined_df = pd.merge(cve_df, trivy_combined_df, how='outer', left_on='id', right_on='VulnerabilityID')
    return combined_df

def clean_data(combined_df):
    # Combine summary and description for text processing
    combined_df['combined_summary'] = combined_df['summary'] + ' ' + combined_df['Description']

    # Separate columns by dtype
    object_cols = ['summary', 'Description', 'combined_summary', 'Severity', 'PkgName']

    combined_df['cvss'] = combined_df['cvss'].fillna(combined_df['cvss'].mean())
    combined_df[object_cols] = combined_df[object_cols].fillna('')

    # Combine summary and description for text processing
    combined_df['combined_summary'] = combined_df['summary'] + ' ' + combined_df['Description']
    return combined_df

def prepare_preprocessor():
    # Define features
    text_features = 'combined_summary'
    categorical_features = ['Severity', 'PkgName']
    numeric_features = ['cvss']

    # Create the preprocessing pipeline
    text_transformer = Pipeline(steps=[
        ('tfidf', TfidfVectorizer(max_features=5000))
    ])

    categorical_transformer = Pipeline(steps=[
        ('onehot', OneHotEncoder(handle_unknown='ignore'))
    ])

    preprocessor = ColumnTransformer(transformers=[
        ('text', text_transformer, text_features),
        ('cat', categorical_transformer, categorical_features),
        ('num', StandardScaler(), numeric_features)
    ])
    return preprocessor

def main():
    data = collect_trivy_cve_data()
    cleaned_data = clean_data(data)
    preprocessor = prepare_preprocessor()

    # Define features and target
    X = cleaned_data[['cvss', 'combined_summary', 'Severity', 'PkgName']]
    y = pd.cut(cleaned_data['cvss'], bins=[0, 3.9, 6.9, 10], labels=['low', 'medium', 'high'])
    print("NaN values in y after pd.cut:", y.isnull().sum())

    y = y.fillna('low')

    # Transform the data
    X_processed = preprocessor.fit_transform(X)

    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X_processed, y, test_size=0.2, random_state=42)

    # Train the Random Forest model
    rf_model = RandomForestClassifier(n_estimators=50, max_depth=20, random_state=42)
    rf_model.fit(X_train, y_train)

    # Evaluate the model
    y_pred = rf_model.predict(X_test)
    print("Random Forest Classifier Accuracy:", accuracy_score(y_test, y_pred))
    print("Classification Report:\n", classification_report(y_test, y_pred))

    # Save the model
    os.makedirs('../models', exist_ok=True)
    joblib.dump(rf_model, '../models/CVE-trivy_model.pkl')
    joblib.dump(preprocessor, '../models/CVE-trivy_preprocessor.pkl')

    print("Random Forest model trained and saved successfully.")
    
if __name__ == "__main__":
    main()
