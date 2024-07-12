import pandas as pd
import numpy as np
import joblib
from keras.models import load_model
from data_collection.run_time import get_container_data

# Load preprocessors and models
runtime_preprocessors = {
    'UNSW-NB15': joblib.load('models/UNSW-NB15_preprocessor.pkl'),
    'CIC-IDS2017': joblib.load('models/CIC-IDS2017_preprocessor.pkl'),
    'Bot-IoT': joblib.load('models/Bot-IoT_scaler.pkl')
}

runtime_models = {
    'UNSW-NB15': joblib.load('models/UNSW-NB15_model.pkl'),
    'CIC-IDS2017': joblib.load('models/CIC-IDS2017_model.pkl'),
    'Bot-IoT': load_model('models/Bot-IoT_autoencoder_model.keras')
}

label_encoders = {
    'UNSW-NB15': {col: joblib.load(f'models/UNSW-NB15_label_encoder_{col}.pkl') for col in ['proto', 'service', 'state', 'attack_cat']},
    'Bot-IoT': {col: joblib.load(f'models/Bot-IoT_label_encoder_{col}.pkl') for col in ['flgs', 'proto', 'saddr', 'sport', 'daddr', 'dport', 'state', 'category', 'subcategory']}
}

def detect_runtime_anomalies(container_name):
    # Collect runtime data
    data = get_container_data(container_name)
    runtime_df, logs, network_df = data['RuntimeData'], data['Logs'], data['NetworkTraffic']
    
    # UNSW-NB15
    unsw_data = runtime_df.copy()
    for col, encoder in label_encoders['UNSW-NB15'].items():
        if col in unsw_data.columns:
            unsw_data[col] = encoder.transform(unsw_data[col].astype(str))
    unsw_data_processed = runtime_preprocessors['UNSW-NB15'].transform(unsw_data)
    unsw_predictions = runtime_models['UNSW-NB15'].predict(unsw_data_processed)

    # CIC-IDS2017
    cic_data = runtime_df.copy()
    for col in runtime_preprocessors['CIC-IDS2017'].transformers[0][2]:
        if col in cic_data.columns:
            cic_data[col] = cic_data[col].astype(str)
    cic_data_processed = runtime_preprocessors['CIC-IDS2017'].transform(cic_data)
    cic_predictions = runtime_models['CIC-IDS2017'].predict(cic_data_processed)

    # Bot-IoT
    bot_data = network_df.copy()
    for col, encoder in label_encoders['Bot-IoT'].items():
        if col in bot_data.columns:
            bot_data[col] = encoder.transform(bot_data[col].astype(str))
    bot_data_processed = runtime_preprocessors['Bot-IoT'].transform(bot_data)
    reconstructions = runtime_models['Bot-IoT'].predict(bot_data_processed)
    reconstruction_error = np.mean(np.square(bot_data_processed - reconstructions), axis=1)
    bot_predictions = (reconstruction_error > 0.5).astype(int)  # Example threshold

    # Aggregate predictions
    all_predictions = {
        'UNSW-NB15': unsw_predictions,
        'CIC-IDS2017': cic_predictions,
        'Bot-IoT': bot_predictions
    }
    return all_predictions

def main():
    container_name = input("Enter the Docker container name: ")
    build_vulnerabilities = detect_runtime_anomalies(container_name)
    print(build_vulnerabilities)
    
if __name__ == "__main__":
    main()
