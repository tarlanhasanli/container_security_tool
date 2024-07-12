import pandas as pd
import joblib
import numpy as np
import os
import glob

from sklearn.ensemble import RandomForestClassifier
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import StandardScaler, LabelEncoder
from xgboost import XGBClassifier
from keras.models import Model
from keras.layers import Input, Dense
from keras.optimizers import Adam

base_url = '' # enter base url

def build_unsw_nb15_models():
    # Load the data
    unsw_train = pd.read_parquet(f"{base_url}/UNSW-NB15/UNSW_NB15_training-set.parquet")
    unsw_test = pd.read_parquet(f"{base_url}/UNSW-NB15/UNSW_NB15_testing-set.parquet")
    unsw_data = pd.concat([unsw_train, unsw_test], ignore_index=True)

    # Preprocess the data
    categorical_columns = ['proto', 'service', 'state', 'attack_cat']
    label_encoders = {col: LabelEncoder() for col in categorical_columns}
    for col in categorical_columns:
        unsw_data[col] = label_encoders[col].fit_transform(unsw_data[col])

    # Define features and target
    X = unsw_data.drop(columns=['label'])
    y = unsw_data['label']

    # Create the preprocessor pipeline
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), X.columns)
        ])

    # Fit the preprocessor and transform the data
    X_processed = preprocessor.fit_transform(X)

    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    # Train the model
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)

    # Evaluate the model
    y_pred = rf.predict(X_test)
    print(classification_report(y_test, y_pred))

    # Save the trained model, preprocessor, and label encoders
    joblib.dump(rf, '../models/UNSW-NB15_model.pkl')
    joblib.dump(preprocessor, '../models/UNSW-NB15_preprocessor.pkl')
    for col, encoder in label_encoders.items():
        joblib.dump(encoder, f'../models/UNSW-NB15_label_encoder_{col}.pkl')

def build_cic_ids2017_models():
    # Combine CSV files
    path = f"{base_url}/CICDS 2017"
    all_files = glob.glob(path + "/*.csv")
    cic_data = pd.concat((pd.read_csv(f) for f in all_files), ignore_index=True)

    # Preprocess the data
    cic_data.fillna(0, inplace=True)

    # Trim column names
    cic_data.columns = cic_data.columns.str.strip()

    # Replace infinity values with NaN
    cic_data.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Convert categorical columns to numeric
    categorical_columns = cic_data.select_dtypes(include=['object']).columns
    cic_data[categorical_columns] = cic_data[categorical_columns].apply(LabelEncoder().fit_transform)

    # Define features and target
    X = cic_data.drop(columns=['Label'])
    y = LabelEncoder().fit_transform(cic_data['Label'])

    # Create the preprocessor pipeline
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), X.columns)
        ])

    # Fit the preprocessor and transform the data
    X_processed = preprocessor.fit_transform(X)

    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X_processed, y, test_size=0.3, random_state=42)

    # Train the model
    xgb = XGBClassifier(use_label_encoder=False, eval_metric='logloss', random_state=42)
    xgb.fit(X_train, y_train)

    # Evaluate the model
    y_pred = xgb.predict(X_test)
    print(classification_report(y_test, y_pred))

    # Save the trained XGBClassifier model
    joblib.dump(preprocessor, '../models/CIC-IDS2017_preprocessor.pkl')
    joblib.dump(xgb, '../models/CIC-IDS2017_model.pkl')

def build_bot_iot_models():
    # path to Bot_IoT dataset
    folder_path = f"{base_url}/bot_iot"

    # Columns to drop due to 0 non-null values
    columns_to_drop = ['smac', 'dmac', 'soui', 'doui', 'sco', 'dco']

    # Initialize StandardScaler
    scaler = StandardScaler()

    # Initialize LabelEncoders for categorical columns
    categorical_cols = ['flgs', 'proto', 'saddr', 'sport', 'daddr', 'dport', 'state', 'category', 'subcategory']
    label_encoders = {col: LabelEncoder() for col in categorical_cols}

    dtype_dict = {5: str, 7: str}

    # Variable to check if encoders are fitted
    scaler_fitted = False

    # Define the autoencoder model
    input_dim = None  # Will be set after the first batch
    input_layer = None
    autoencoder = None

    # Process each file separately
    for file_path in glob.glob(f"{folder_path}/*.csv"):
        chunk = pd.read_csv(file_path, dtype=dtype_dict, low_memory=False)
        
        # Drop columns with 0 non-null values
        chunk.drop(columns=columns_to_drop, inplace=True)
        
        # Handle missing values
        chunk.fillna(0, inplace=True)
        
        # Convert categorical columns to strings to ensure uniform data types
        for col in categorical_cols:
            if col in chunk.columns:
                chunk[col] = chunk[col].astype(str)
        
        # Encode categorical columns using LabelEncoder
        for col in categorical_cols:
            if col in chunk.columns:
                chunk[col] = label_encoders[col].fit_transform(chunk[col])
        
        # Ensure all columns are numeric
        chunk = chunk.apply(pd.to_numeric, errors='coerce')
        
        # Replace any remaining NaNs or infinite values
        chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
        chunk.fillna(0, inplace=True)
        
        # Define features (drop non-feature columns)
        X_chunk = chunk.drop(columns=['attack'], errors='ignore')
        X_chunk = scaler.fit_transform(X_chunk)
        
        # Initialize autoencoder after determining input_dim from the first chunk
        if input_dim is None:
            input_dim = X_chunk.shape[1]
            input_layer = Input(shape=(input_dim,))
            encoded = Dense(64, activation='relu')(input_layer)
            encoded = Dense(32, activation='relu')(encoded)
            encoded = Dense(16, activation='relu')(encoded)
            decoded = Dense(32, activation='relu')(encoded)
            decoded = Dense(64, activation='relu')(decoded)
            decoded = Dense(input_dim, activation='sigmoid')(decoded)
            
            autoencoder = Model(input_layer, decoded)
            optimizer = Adam(learning_rate=0.0001)  # Reduced learning rate
            autoencoder.compile(optimizer=optimizer, loss='mean_squared_error')
        
        # Train the autoencoder incrementally
        autoencoder.fit(X_chunk, X_chunk, epochs=5, batch_size=256, shuffle=True)
        
    # Save the autoencoder model
    autoencoder.save('../models/Bot-IoT_autoencoder_model.keras')

    # Save the scaler and encoder for future use
    joblib.dump(scaler, '../models/Bot-IoT_scaler.pkl')
    for col, encoder in label_encoders.items():
        joblib.dump(encoder, f'../models/Bot-IoT_label_encoder_{col}.pkl')

def main():
    os.makedirs('../models', exist_ok=True)

    build_unsw_nb15_models()
    build_cic_ids2017_models()
    build_bot_iot_models()

if __name__ == "__main__":
    main()