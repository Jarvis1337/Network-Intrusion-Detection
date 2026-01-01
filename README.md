*<h1 align="">🚀 Network Intrusion Detection System (NIDS) <3...</h1>*

*An intelligent Network Intrusion Detection System (NIDS). It is designed to monitor network traffic for suspicious activity and known threats, utilizing machine learning algorithms to classify traffic patterns as either normal or intrusive. The application provides a user-friendly interface built with Streamlit.*


> [!IMPORTANT]  
> *Before you begin, ensure you have the following installed on your local machine:*
>
> - ***Python:** The latest version of Python (3.14 or higher is recommended).*
> - ***Git:** Version control system to clone the repository.*
    
----

*<h2>🏁 Here are the installation steps : ----</h2>*

*Follow these steps to set up the project environment and install the necessary dependencies.*

### *1. Clone the Repository*

*First, clone the project repository from GitHub to your local machine and navigate into the project directory.*

```Bash
git clone https://github.com/Jarvis1337/Network-Intrusion-Detection.git
cd Network-Intrusion-Detection
```

### *2. Create a Virtual Environment*

*It is highly recommended to use a virtual environment to manage dependencies for this project. This keeps your project libraries isolated from your global Python installation.*

*Run the following command to create a virtual environment named `venv`:*

```Bash
python -m venv venv
```

### *3. Activate the Virtual Environment*

*Once the virtual environment is created, you need to activate it. The command differs depending on your operating system.*
- ***For Linux / macOS (Bash/Zsh):***

```Bash
source venv/bin/activate
```

*For Windows (PowerShell/Command Prompt):*
- *If you are using PowerShell, you might need to allow script execution first. Then activate the environment:*

```PowerShell
# Optional: Run this if you get a permission error
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process

# Activate the environment
.\venv\Scripts\activate
```

> [!NOTE]  
> *_Once activated, you should see `(venv)` appear at the beginning of your terminal prompt._*

### *4. Install Dependencies*

*With the virtual environment active, install all the required Python packages listed in the `requirements.txt` file using `pip`.*

```Bash
pip install -r requirements.txt
```

----

*<h2>🚀 Here are the Usage steps: ----</h2>*

### *Running the Application:*

- *To start the Network Intrusion Detection System interface, use the `streamlit` command pointing to the main application file (`nids_app.py`).*

```bash
streamlit run nids_app.py
```

### *Accessing the Interface:*
- *After running the command, Streamlit will spin up a local server.6 You can access the NIDS dashboard by opening the URL provided in the terminal (usually `http://localhost:8501`) in your web browser.*

----

## *Troubleshooting*

> [!CAUTION]
> - ***'streamlit' is not recognized:** Ensure you have activated your virtual environment before running the command. If the issue persists, try running `python -m streamlit run nids_app.py`.*
>
> - ***Permission Denied on Windows:** If you cannot activate the virtual environment, ensure you ran the `Set-ExecutionPolicy` command mentioned in Step 3.*
    
----
> *<h4 align="center">⭐ Feel free to Star the Repository if this helped you!</h4>*
----
> *<h4 align="center">Network-Intrusion-Detection (NIDS) © 2026 by ~Jarvis is licensed under GNU General Public License v3.0 and Attribution 4.0 International</h4>*
