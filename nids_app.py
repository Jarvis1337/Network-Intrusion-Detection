import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import seaborn as sns

st.set_page_config(page_title="Real AI-NIDS Dashboard", layout="wide")

st.title("🛡️ AI-Based NIDS (Production Mode)")
st.markdown("This system trains on the **Real CIC-IDS2017 Dataset** to detect DDoS attacks.")

st.sidebar.header("Control Panel")

@st.cache_data # Cache data to speed up reloading
def load_data():
    filename = 'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv' # Dataset Using: Intrusion detection evaluation dataset (CIC-IDS2017)
    
    try:
        df = pd.read_csv(filename)
    except FileNotFoundError:
        st.error(f"Error: '{filename}' not found. Please place the CSV file in the project folder.")
        return None

    df.columns = df.columns.str.strip()
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    return df

if 'model' not in st.session_state:
    st.session_state['model'] = None
    st.session_state['accuracy'] = 0

if st.sidebar.button("Train Model on Real Data"):
    with st.spinner("Loading heavy dataset and Training... (This may take time)"):
        df = load_data()
        
        if df is not None:
            features = ['Destination Port', 'Flow Duration', 'Total Fwd Packets', 
                        'Total Backward Packets', 'Total Length of Fwd Packets', 
                        'Packet Length Mean', 'Fwd Packet Length Max']
            
            available_features = [c for c in features if c in df.columns]
            
            X = df[available_features]
            y = df['Label']
            
            le = LabelEncoder()
            y = le.fit_transform(y)
            st.session_state['le'] = le

            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
            
            # Model Training
            rf_model = RandomForestClassifier(n_estimators=20, random_state=42, n_jobs=-1)
            rf_model.fit(X_train, y_train)
            
            # Evaluation
            y_pred = rf_model.predict(X_test)
            acc = accuracy_score(y_test, y_pred)
            
            st.session_state['model'] = rf_model
            st.session_state['accuracy'] = acc
            st.session_state['X_test'] = X_test
            st.session_state['y_test'] = y_test
            st.sidebar.success(f"Training Complete! Accuracy: {acc*100:.2f}%")

col1, col2 = st.columns(2)

with col1:
    st.subheader("📊 Model Performance")
    if st.session_state['model']:
        st.metric("Accuracy", f"{st.session_state['accuracy']*100:.2f}%")
        
        st.write("Confusion Matrix:")
        cm = confusion_matrix(st.session_state['y_test'], st.session_state['model'].predict(st.session_state['X_test']))
        fig, ax = plt.subplots()
        sns.heatmap(cm, annot=True, fmt='d', cmap='Reds', ax=ax)
        st.pyplot(fig)
    else:
        st.info("Please download the CSV and click 'Train Model' to start.")

with col2:
    st.subheader("🔎 Real Traffic Analysis")
    if st.session_state['model']:
        st.write("Test the model with values similar to the dataset:")
        
        dest_port = st.number_input("Destination Port", 0, 65535, 80)
        flow_dur = st.number_input("Flow Duration", 0, 10000000, 5000)
        fwd_pkts = st.number_input("Total Fwd Packets", 0, 10000, 5)
        bwd_pkts = st.number_input("Total Backward Packets", 0, 10000, 3)
        len_fwd = st.number_input("Total Length Fwd Packets", 0, 100000, 200)
        pkt_mean = st.number_input("Packet Length Mean", 0.0, 2000.0, 50.0)
        fwd_max = st.number_input("Fwd Packet Length Max", 0, 2000, 100)

        if st.button("Predict Attack"):
            input_data = pd.DataFrame([[dest_port, flow_dur, fwd_pkts, bwd_pkts, len_fwd, pkt_mean, fwd_max]], 
                                      columns=['Destination Port', 'Flow Duration', 'Total Fwd Packets', 
                                               'Total Backward Packets', 'Total Length of Fwd Packets', 
                                               'Packet Length Mean', 'Fwd Packet Length Max'])
            
            pred_code = st.session_state['model'].predict(input_data)[0]
            pred_label = st.session_state['le'].inverse_transform([pred_code])[0]
            
            if "BENIGN" in pred_label:
                st.success(f"✅ Traffic is SAFE ({pred_label})")
            else:
                st.error(f"🚨 ALERT: Attack Detected! Type: {pred_label}")