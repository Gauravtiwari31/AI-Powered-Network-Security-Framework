import pandas as pd
import os
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
# Import StratifiedKFold
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.utils import resample
import joblib


DATASET_PATH = './datasets/CSE-CIC-IDS2018-Dataset/Processed_CSVs/'


SELECTED_CSV_FILES = [
    'Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv',
]

COLUMNS_TO_DROP = [
    'Flow ID', 'Source IP', 'Destination IP', 'Timestamp',
    'Flow Pkts/s', 'Flow Byts/s',
    'Fwd Pkts/s', 'Bwd Pkts/s',
    'Subflow Fwd Byts', 'Subflow Bwd Byts',
    'Subflow Fwd Pkts', 'Subflow Bwd Pkts',
]

# --- Model Training Logic ---


def train_models():
    all_files_to_load = [os.path.join(
        DATASET_PATH, f) for f in SELECTED_CSV_FILES if os.path.exists(os.path.join(DATASET_PATH, f))]

    if not all_files_to_load:
        print(
            f"Error: No selected CSV files found in {DATASET_PATH}. Please check SELECTED_CSV_FILES list and path.")
        return

    print(
        f"[*] Found {len(all_files_to_load)} selected CSV files. Loading data...")
    list_df = []
    for f in all_files_to_load:
        try:
            df = pd.read_csv(f, low_memory=False, encoding='latin1')
            list_df.append(df)
        except Exception as e:
            print(f"[-] Error loading {f}: {e}")
            continue

    if not list_df:
        print("Error: No data loaded from CSVs. Exiting.")
        return

    df = pd.concat(list_df, ignore_index=True)
    print(f"[*] Total DataFrame shape after initial loading: {df.shape}")

    print("\n[*] Starting data preprocessing...")

    df.columns = df.columns.str.strip()

    df['Label'] = df['Label'].replace('Benign', 0)
    df.loc[df['Label'] != 0, 'Label'] = 1

    print(
        f"Label distribution after binary conversion:\n{df['Label'].value_counts()}")

    initial_cols = set(df.columns)
    df = df.drop(
        columns=[col for col in COLUMNS_TO_DROP if col in df.columns], errors='ignore')
    final_cols = set(df.columns)
    dropped_cols_actual = list(initial_cols - final_cols)
    if dropped_cols_actual:
        print(f"[*] Dropped columns: {dropped_cols_actual}")
    else:
        print("[*] No specified columns were dropped (perhaps they weren't present or were already handled).")

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    print(
        f"[*] Replaced Inf values with NaN. Total NaN after Inf replacement: {df.isnull().sum().sum()}")

    df.fillna(0, inplace=True)
    print(
        f"[*] Missing values filled with 0. Total NaN after fillna: {df.isnull().sum().sum()}")

    for col in df.columns.drop('Label'):
        df[col] = pd.to_numeric(df[col], errors='coerce')
    df.fillna(0, inplace=True)
    print("[*] All feature columns ensured to be numeric.")

    df_majority = df[df.Label == 0]
    df_minority = df[df.Label == 1]

    if not df_minority.empty and len(df_majority) > len(df_minority) * 2:
        print(
            f"[*] Imbalanced data detected. Majority (Benign): {len(df_majority)}, Minority (Attack): {len(df_minority)}")
        df_majority_undersampled = resample(df_majority,
                                            replace=False,
                                            n_samples=len(df_minority),
                                            random_state=42)

        df_balanced = pd.concat([df_majority_undersampled, df_minority])
        print(
            f"[*] Dataset balanced using undersampling. New shape: {df_balanced.shape}")
        print(
            f"New label distribution:\n{df_balanced['Label'].value_counts()}")
        df = df_balanced
    else:
        print(
            "[*] Dataset imbalance not severe enough for undersampling or minority class is empty.")

    X = df.drop('Label', axis=1)
    y = df['Label']

    # --- Corrected placement for FINAL_FEATURE_COLUMNS ---
    numeric_cols_final = X.select_dtypes(include=np.number).columns.tolist()
    print(f"\nFINAL FEATURE COLUMNS (ORDER MATTERS): {numeric_cols_final}\n")
    # --- END Corrected placement ---

    # Ensure X only contains numeric columns (should already be due to previous step)
    X = X[numeric_cols_final]
    print(f"[*] Final feature set shape after preprocessing: {X.shape}")
    print(f"[*] Final label set shape: {y.shape}")

    # --- Cross-Validation Setup ---
    # Using StratifiedKFold to maintain class proportions in each fold
    cv = StratifiedKFold(n_splits=5, shuffle=True,
                         random_state=42)  # 5 folds is common

    # --- 4. Model Training and Evaluation with Cross-Validation ---
    print("\n[*] Training Machine Learning Models (with Cross-Validation for robust evaluation)...")

    # --- Random Forest Classifier Cross-Validation ---
    print("\n--- Random Forest Classifier (Cross-Validation) ---")
    rf_model_cv_eval = RandomForestClassifier(
        n_estimators=50, max_depth=15, random_state=42, n_jobs=-1)

    # Use cross_val_score to get accuracy scores for each fold
    scores_rf = cross_val_score(
        rf_model_cv_eval, X, y, cv=cv, scoring='accuracy', n_jobs=-1)
    # Mean accuracy with 95% confidence interval
    print(
        f"RF CV Accuracy: {scores_rf.mean():.4f} (+/- {scores_rf.std() * 2:.4f})")

    # No need for y_test and y_pred_rf metrics here, as CV handles validation internally.
    # We will train the final model on the full X, y later.

    # --- Logistic Regression Cross-Validation ---
    print("\n--- Logistic Regression (Cross-Validation) ---")
    # Scale the full X data before passing to cross_val_score for Logistic Regression
    scaler_cv_eval = StandardScaler()
    X_scaled_cv_eval = scaler_cv_eval.fit_transform(X)

    lr_model_cv_eval = LogisticRegression(
        random_state=42, solver='liblinear', n_jobs=1)
    scores_lr = cross_val_score(
        lr_model_cv_eval, X_scaled_cv_eval, y, cv=cv, scoring='accuracy', n_jobs=-1)
    print(
        f"LR CV Accuracy: {scores_lr.mean():.4f} (+/- {scores_lr.std() * 2:.4f})")

    # --- 5. Train Final Models on Full Data and Save ---
    # After robust evaluation with CV, train the final models on the entire processed dataset (X, y)
    # This is the model that will be used in your firewall.
    print(
        "\n[*] Training final models on the entire processed dataset for deployment...")

    # Random Forest Final Model
    rf_model = RandomForestClassifier(
        n_estimators=50, max_depth=15, random_state=42, n_jobs=-1)
    rf_model.fit(X, y)  # Train on full data
    print("[*] Final Random Forest model trained.")

    # Logistic Regression Final Model
    scaler = StandardScaler()  # Create a new scaler for the final model
    X_scaled_final = scaler.fit_transform(X)  # Fit scaler on full data
    lr_model = LogisticRegression(
        random_state=42, solver='liblinear', n_jobs=1)
    lr_model.fit(X_scaled_final, y)  # Train on full data
    print("[*] Final Logistic Regression model trained.")

    print("\n[*] Saving trained models and scaler...")
    MODEL_DIR = './trained_models'
    os.makedirs(MODEL_DIR, exist_ok=True)

    joblib.dump(rf_model, os.path.join(MODEL_DIR, 'random_forest_model.pkl'))
    joblib.dump(lr_model, os.path.join(
        MODEL_DIR, 'logistic_regression_model.pkl'))
    # Save this scaler as it's needed for LR inference
    joblib.dump(scaler, os.path.join(MODEL_DIR, 'scaler.pkl'))
    print(f"Models and scaler saved to {MODEL_DIR}/")


if __name__ == "__main__":
    train_models()
