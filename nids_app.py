import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

# --- Page Config ---
st.set_page_config(page_title="AI-NIDS Dashboard", layout="wide")

# --- Title and Introduction ---
st.title("🛡️ AI-Based Network Intrusion Detection System")
st.markdown("""
This system uses **Machine Learning (Random Forest)** to detect network anomalies.
It operates in **Simulation Mode**, generating synthetic traffic data for demonstration.
""")

# --- Sidebar ---
st.sidebar.header("Control Panel")

# --- Function to Generate Synthetic Data (Simulation Mode) ---
def generate_data(n_samples=2000):
    np.random.seed(42)
    packet_size = np.random.randint(40, 1500, n_samples)
    time_interval = np.random.exponential(scale=1.0, size=n_samples)
    protocol = np.random.choice([0, 1, 2], n_samples, p=[0.6, 0.3, 0.1])
    flags = np.random.choice([0, 1, 2], n_samples)
    
    labels = []
    for i in range(n_samples):
        if (packet_size[i] < 100) and (time_interval[i] < 0.1) and (flags[i] == 1):
            labels.append(1) # Attack
        elif (protocol[i] == 2) and (packet_size[i] > 1000):
            labels.append(1) # Ping of Death scenario
        else:
            labels.append(0) # Normal
            
    df = pd.DataFrame({
        'Packet_Size': packet_size,
        'Time_Interval': time_interval,
        'Protocol': protocol,
        'Flag': flags,
        'Label': labels
    })
    return df

# --- Model Training Section ---
if 'model' not in st.session_state:
    st.session_state['model'] = None
    st.session_state['accuracy'] = 0

if st.sidebar.button("Train Model Now"):
    with st.spinner("Generating Data & Training Model..."):
        df = generate_data()
        
        X = df.drop('Label', axis=1)
        y = df['Label']
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
        
        rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        rf_model.fit(X_train, y_train)
        
        y_pred = rf_model.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        
        st.session_state['model'] = rf_model
        st.session_state['accuracy'] = acc
        st.session_state['X_test'] = X_test # Saving for metrics visualization
        st.session_state['y_test'] = y_test
        
    st.sidebar.success(f"Model Trained! Accuracy: {acc*100:.2f}%")

# --- Main Dashboard Area ---

col1, col2 = st.columns(2)

with col1:
    st.subheader("📊 Training Metrics")
    if st.session_state['model']:
        st.metric(label="Model Accuracy", value=f"{st.session_state['accuracy']*100:.2f}%")
        
        st.write("Confusion Matrix:")
        cm = confusion_matrix(st.session_state['y_test'], st.session_state['model'].predict(st.session_state['X_test']))
        fig, ax = plt.subplots()
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax)
        st.pyplot(fig)
    else:
        st.info("Please click 'Train Model Now' in the sidebar to start.")

with col2:
    st.subheader("🕵️ Live Traffic Simulator")
    st.write("Input network packet parameters to test the model:")
    
    # User Inputs for Prediction
    p_size = st.slider("Packet Size (bytes)", 40, 1500, 64)
    t_interval = st.number_input("Time Interval (ms)", 0.0, 10.0, 0.5)
    proto = st.selectbox("Protocol", options=[0, 1, 2], format_func=lambda x: {0: "TCP", 1: "UDP", 2: "ICMP"}[x])
    flag = st.selectbox("Flag", options=[0, 1, 2], format_func=lambda x: {0: "Normal", 1: "SYN", 2: "ACK"}[x])
    
    if st.button("Analyze Packet"):
        if st.session_state['model'] is None:
            st.error("Model is not trained yet!")
        else:
            input_data = pd.DataFrame({
                'Packet_Size': [p_size],
                'Time_Interval': [t_interval],
                'Protocol': [proto],
                'Flag': [flag]
            })
            
            prediction = st.session_state['model'].predict(input_data)[0]
            probability = st.session_state['model'].predict_proba(input_data)[0][1]
            
            st.markdown("---")
            if prediction == 1:
                st.error(f"🚨 ALERT: Malicious Traffic Detected! (Confidence: {probability*100:.2f}%)")
            else:
                st.success(f"✅ Safe Traffic. (Confidence: {(1-probability)*100:.2f}%)")

st.markdown("---")
st.caption("AI-NIDS Project | Based on Random Forest Algorithm")