import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import seaborn as sns
import matplotlib.pyplot as plt
import time
import os

st.set_page_config(
    page_title="AI Network Intrusion Detection System",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI-Based Network Intrusion Detection System")
st.markdown("""
**Real-time Network Security Monitoring using Machine Learning**

This system uses Random Forest algorithm to detect network intrusions using the CIC-IDS2017 dataset.
""")

st.sidebar.header("⚙️ Control Panel")
st.sidebar.markdown("---")

# Function to load CSV data
@st.cache_data
def load_csv_data(file_path=None):
    """Load data from CSV file or use simulation"""
    
    csv_files = [f for f in os.listdir('.') if f.endswith('.csv')]
    
    if file_path and os.path.exists(file_path):
        csv_file = file_path
    elif csv_files:
        csv_file = csv_files[0]
    else:
        st.warning("⚠️ No CSV file found. Using simulated data instead.")
        st.info("📥 To use real data, download CIC-IDS2017 dataset and place CSV in project folder")
        return generate_simulation_data(2000), False
    
    try:
        st.info(f"📂 Loading data from: {csv_file}")
        df = pd.read_csv(csv_file)
        
        # Clean column names (remove extra spaces)
        df.columns = df.columns.str.strip()
        
        st.success(f"✅ Successfully loaded {len(df)} records from CSV!")
        return df, True
        
    except Exception as e:
        st.error(f"❌ Error loading CSV: {str(e)}")
        st.info("Using simulated data instead...")
        return generate_simulation_data(2000), False

# Function to generate simulated data (backup)
def generate_simulation_data(num_samples=1000):
    """Generate realistic network traffic data for training"""
    np.random.seed(42)
    
    # Normal Traffic (70%)
    normal_samples = int(num_samples * 0.7)
    normal_data = {
        'Flow Duration': np.random.normal(2000000, 500000, normal_samples),
        'Total Fwd Packets': np.random.randint(1, 50, normal_samples),
        'Total Backward Packets': np.random.randint(1, 50, normal_samples),
        'Total Length of Fwd Packets': np.random.normal(1000, 300, normal_samples),
        'Total Length of Bwd Packets': np.random.normal(1000, 300, normal_samples),
        'Fwd Packet Length Mean': np.random.normal(500, 150, normal_samples),
        'Flow Bytes/s': np.random.normal(10000, 3000, normal_samples),
        'Flow Packets/s': np.random.normal(50, 15, normal_samples),
        'Label': ['BENIGN'] * normal_samples
    }
    
    # Attack Traffic (30%)
    attack_samples = num_samples - normal_samples
    attack_data = {
        'Flow Duration': np.random.normal(500000, 200000, attack_samples),
        'Total Fwd Packets': np.random.randint(50, 500, attack_samples),
        'Total Backward Packets': np.random.randint(0, 10, attack_samples),
        'Total Length of Fwd Packets': np.random.normal(5000, 1000, attack_samples),
        'Total Length of Bwd Packets': np.random.normal(100, 50, attack_samples),
        'Fwd Packet Length Mean': np.random.normal(1500, 500, attack_samples),
        'Flow Bytes/s': np.random.normal(50000, 10000, attack_samples),
        'Flow Packets/s': np.random.normal(200, 50, attack_samples),
        'Label': ['DDoS'] * attack_samples
    }
    
    df_normal = pd.DataFrame(normal_data)
    df_attack = pd.DataFrame(attack_data)
    df = pd.concat([df_normal, df_attack], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    return df

# Preprocess data
def preprocess_data(df, is_real_csv=True):
    """Preprocess the dataset for training"""
    
    data = df.copy()
    
    data = data.replace([np.inf, -np.inf], np.nan)
    data = data.fillna(0)
    
    if 'Label' in data.columns:
        label_col = 'Label'
    elif ' Label' in data.columns:
        label_col = ' Label'
    else:
        st.error("❌ Label column not found!")
        return None, None
    
    data['Attack'] = data[label_col].apply(lambda x: 0 if 'BENIGN' in str(x).upper() else 1)
    
    feature_columns = []
    
    # Common feature names in CIC-IDS2017
    possible_features = [
        'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
        'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
        'Fwd Packet Length Mean', 'Bwd Packet Length Mean',
        'Flow Bytes/s', 'Flow Packets/s', 'Fwd IAT Mean',
        'Bwd IAT Mean', 'Fwd PSH Flags', 'Bwd PSH Flags',
        'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
        'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
        'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance'
    ]
    
    # Find available features
    for feature in possible_features:
        if feature in data.columns:
            feature_columns.append(feature)
        elif f' {feature}' in data.columns:  # Handle space prefix
            feature_columns.append(f' {feature}')
    
    if len(feature_columns) < 5:
        numeric_cols = data.select_dtypes(include=[np.number]).columns
        feature_columns = [col for col in numeric_cols if col not in [label_col, 'Attack']]
    
    # Limit to top 15 features for performance
    feature_columns = feature_columns[:15]
    
    if not feature_columns:
        st.error("❌ No valid features found!")
        return None, None
    
    X = data[feature_columns]
    y = data['Attack']
    
    return X, y, feature_columns

@st.cache_resource
def train_model(X, y):
    """Train Random Forest Classifier"""
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_split=5,
        random_state=42,
        n_jobs=-1
    )
    
    with st.spinner("🤖 Training Random Forest model..."):
        model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    return model, X_test, y_test, y_pred, accuracy

def main():
    st.sidebar.subheader("📁 Dataset Selection")
    
    csv_files = [f for f in os.listdir('.') if f.endswith('.csv')]
    
    if csv_files:
        selected_file = st.sidebar.selectbox("Select CSV File:", csv_files)
        use_csv = True
    else:
        st.sidebar.warning("No CSV files found in directory")
        st.sidebar.info("Place CIC-IDS2017 CSV file in project folder")
        selected_file = None
        use_csv = False
    
    st.sidebar.markdown("---")
    st.sidebar.subheader("📊 Model Training")
    
    if st.sidebar.button("🚀 Train Model Now", use_container_width=True):
        st.session_state['model_trained'] = True
        st.session_state['selected_file'] = selected_file
    
    # Load data
    data, is_real = load_csv_data(selected_file if use_csv else None)
    
    # Display dataset info
    with st.expander("📁 View Dataset Information", expanded=True):
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Records", len(data))
        with col2:
            st.metric("Features", len(data.columns) - 1)
        with col3:
            if 'Label' in data.columns:
                benign_count = len(data[data['Label'].str.contains('BENIGN', case=False, na=False)])
            elif ' Label' in data.columns:
                benign_count = len(data[data[' Label'].str.contains('BENIGN', case=False, na=False)])
            else:
                benign_count = 0
            st.metric("Normal Traffic", benign_count)
        with col4:
            attack_count = len(data) - benign_count
            st.metric("Attack Traffic", attack_count)
        
        st.write("**Sample Data (First 5 rows):**")
        st.dataframe(data.head(), use_container_width=True)
        
        if 'Label' in data.columns or ' Label' in data.columns:
            label_col = 'Label' if 'Label' in data.columns else ' Label'
            st.write("**Attack Types Distribution:**")
            attack_dist = data[label_col].value_counts()
            st.bar_chart(attack_dist)
    
    # Train model if button clicked
    if st.session_state.get('model_trained', False):
        # Preprocess data
        result = preprocess_data(data, is_real)
        
        if result is None:
            st.error("Failed to preprocess data!")
            return
        
        X, y, feature_cols = result
        
        st.info(f"Using {len(feature_cols)} features for training")
        
        model, X_test, y_test, y_pred, accuracy = train_model(X, y)
        
        st.success(f"✅ Model trained successfully! Accuracy: **{accuracy*100:.2f}%**")
        
        st.session_state['model'] = model
        st.session_state['feature_cols'] = feature_cols
        st.session_state['X_sample'] = X.iloc[0]
        
        # Model Performance
        st.subheader("📈 Model Performance Metrics")
        
        col1, col2, col3, col4 = st.columns(4)
        
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        
        with col1:
            st.metric("🎯 Accuracy", f"{accuracy*100:.2f}%")
        with col2:
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            st.metric("🔍 Precision", f"{precision*100:.2f}%")
        with col3:
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            st.metric("📊 Recall", f"{recall*100:.2f}%")
        with col4:
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            st.metric("⚡ F1-Score", f"{f1*100:.2f}%")
        
        # Confusion Matrix
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🔢 Confusion Matrix")
            fig, ax = plt.subplots(figsize=(6, 4))
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                        xticklabels=['Normal', 'Attack'],
                        yticklabels=['Normal', 'Attack'])
            plt.ylabel('Actual')
            plt.xlabel('Predicted')
            st.pyplot(fig)
        
        with col2:
            st.subheader("🎯 Feature Importance")
            importance = model.feature_importances_
            feat_imp_df = pd.DataFrame({
                'Feature': feature_cols,
                'Importance': importance
            }).sort_values('Importance', ascending=False).head(10)
            
            fig, ax = plt.subplots(figsize=(6, 4))
            sns.barplot(data=feat_imp_df, y='Feature', x='Importance', palette='viridis')
            plt.title('Top 10 Important Features')
            st.pyplot(fig)
        
        # Live Traffic Simulator
        st.markdown("---")
        st.subheader("🔴 Live Traffic Simulator")
        st.write("Test the model with custom network parameters")
        
        # Create input form based on features
        input_data = {}
        
        cols = st.columns(3)
        for idx, feature in enumerate(feature_cols[:9]):  # Show first 9 features
            with cols[idx % 3]:
                # Get sample value
                sample_val = float(X[feature].median())
                min_val = float(X[feature].min())
                max_val = float(X[feature].max())
                
                # Create slider with reasonable range
                input_data[feature] = st.slider(
                    feature.strip(),
                    min_value=min_val,
                    max_value=max_val,
                    value=sample_val,
                    key=feature
                )
        
        # Fill remaining features with median values
        for feature in feature_cols[9:]:
            input_data[feature] = float(X[feature].median())
        
        if st.button("🔍 Analyze Traffic", use_container_width=True):
            # Create DataFrame
            test_df = pd.DataFrame([input_data])
            
            # Predict
            prediction = model.predict(test_df)[0]
            probability = model.predict_proba(test_df)[0]
            
            # Display result
            st.markdown("### 🎯 Detection Result")
            
            if prediction == 0:
                st.success("✅ **NORMAL TRAFFIC** - No threat detected")
                st.info(f"Confidence: {probability[0]*100:.2f}%")
            else:
                st.error("🚨 **ATTACK DETECTED** - Potential intrusion!")
                st.warning(f"Threat Probability: {probability[1]*100:.2f}%")
                st.write("**Recommended Action:** Block source IP and alert security team")
    
    else:
        st.info("👈 Click **'Train Model Now'** in the sidebar to start")
        
        # Instructions
        st.markdown("---")
        st.subheader("📖 How to Use This System")
        st.markdown("""
        1. **Download CIC-IDS2017 Dataset** from [UNB Website](https://www.unb.ca/cic/datasets/ids-2017.html)
        2. **Place CSV file** in the `Root` dir
        3. **Select the CSV file** from sidebar dropdown
        4. **Click 'Train Model Now'** to train the ML model
        5. **Test with Live Simulator** to detect attacks
        """)

if __name__ == "__main__":
    main()