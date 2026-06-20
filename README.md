# Network Bouncer AI

## Detecting Suspicious Port Scanning in Data Center Traffic

Network Bouncer AI is a cybersecurity analytics tool developed for the Dell Futureminds AI Hackathon.

The system analyzes network traffic logs from the UNSW-NB15 dataset and identifies suspicious hosts that may be performing port scanning or abnormal network behavior.

## Features

* CSV Parsing
* Network Metadata Analysis
* Feature Extraction
* Rule-Based Detection
* Machine Learning Detection (Isolation Forest)
* Risk Scoring Engine
* Severity Classification
* CSV Reporting
* Interactive Streamlit Dashboard

## Technologies

* Python
* Pandas
* Scikit-Learn
* Plotly
* Streamlit

## Run

Generate Report:

python network_bouncer.py

Launch Dashboard:

streamlit run src/dashboard/dashboard.py

## Output

* Suspicious IP Detection
* Risk Score Calculation
* Severity Classification
* ML Predictions
* Interactive Security Dashboard
