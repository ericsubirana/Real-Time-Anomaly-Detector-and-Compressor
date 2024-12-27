import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder, StandardScaler
from joblib import dump, load
import os

# Path to the model file
model_file = "incremental_model.joblib"

# Load the CSV file
def load_dataset(csv_file):
    # Load dataset
    df = pd.read_csv(csv_file, header=None)

    # Define column names (assuming UNSW-NB15 format)
    column_names = [
        "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "state", "dur", "sbytes", "dbytes",
        "sttl", "dttl", "sloss", "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts", "swin",
        "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len", "Sjit",
        "Djit", "Stime", "Ltime", "Sintpkt", "Dintpkt", "tcprtt", "synack", "ackdat", "is_sm_ips_ports",
        "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd", "ct_srv_src",
        "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
        "ct_dst_src_ltm", "attack_cat", "label"
    ]
    df.columns = column_names

    # Drop irrelevant columns (IP addresses, timestamps, etc.)
    df = df.drop(columns=["src_ip", "dst_ip", "Stime", "Ltime"])

    # Handle missing values
    df.fillna(0, inplace=True)

    return df

# Preprocess the dataset
# Preprocess the dataset
def preprocess_data(df):
    # Separate features and labels
    X = df.drop(columns=["attack_cat", "label"])
    y = df["label"]  # Use the binary label (0 for normal, 1 for attack)

    # Encode categorical features
    categorical_columns = X.select_dtypes(include=["object"]).columns
    label_encoders = {}

    for col in categorical_columns:
        # Convert the column to string to ensure uniformity
        X[col] = X[col].astype(str)
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col])
        label_encoders[col] = le

    # Normalize the features for incremental learning
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    return X, y, scaler, label_encoders   #Y is TARGET and X is Features


# Load or initialize the model
def load_or_initialize_model(input_dim):
    if os.path.exists(model_file):
        print("Loading existing model...")
        model = load(model_file)
    else:
        print("No existing model found. Training a new one...")
        model = SGDClassifier(loss="log_loss", random_state=42)  # Logistic Regression with SGD
    return model

# Main training and saving logic
def train_and_save_model(csv_file):
    # Load and preprocess the data
    df = load_dataset(csv_file)
    X, y, scaler, label_encoders = preprocess_data(df)

    # Load or initialize the model
    clf = load_or_initialize_model(X.shape[1])

    # Incrementally train the model
    print("Incrementally training the model...")
    clf.partial_fit(X, y, classes=[0, 1])  # ensures the previously learned patterns are retained while adding new knowledge.

    # Save the model
    dump(clf, model_file)
    print(f"Model saved to {model_file}")

    # Evaluate the model
    y_pred = clf.predict(X)
    accuracy = accuracy_score(y, y_pred)
    print(f"Accuracy: {accuracy:.4f}")
    print("Classification Report:")
    print(classification_report(y, y_pred))

# Example usage
if __name__ == "__main__":
    # Replace 'your_dataset.csv' with the path to your CSV file
    for i in range(1,4):
        csv_file = f"packet_learning/UNSW-NB15_{i}.csv"
        train_and_save_model(csv_file)
  
