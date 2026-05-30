# Dataset Credits: CSE-CIC-IDS2018

This project utilizes the **CSE-CIC-IDS2018** network intrusion detection dataset.

## Description
The CSE-CIC-IDS2018 dataset is a collaborative project between the Communications Security Establishment (CSE) and the Canadian Institute for Cybersecurity (CIC). It is designed to evaluate intrusion detection systems, especially network-based anomaly detectors, by providing diverse and comprehensive benchmark data. It includes benign traffic and seven different attack scenarios: Brute-force, Heartbleed, Botnet, DoS, DDoS, Web attacks, and Infiltration. The dataset includes captured network traffic (PCAPs) and extracted features in CSV format.

## Source and Download
The full dataset can be accessed from AWS S3.

**University Website:** While direct links to the UNB website for download might change, the dataset is officially associated with:
* **Canadian Institute for Cybersecurity (CIC), University of New Brunswick (UNB)**

**AWS S3 Download Instructions:**
To download the pre-processed CSV files (recommended for ML model building due to size), use the AWS CLI.

1.  **Install AWS CLI:**
    * **macOS:**
        ```bash
        curl "[https://awscli.amazonaws.com/AWSCLIV2.pkg](https://awscli.amazonaws.com/AWSCLIV2.pkg)" -o "AWSCLIV2.pkg"
        sudo installer -pkg AWSCLIV2.pkg -target /
        ```
    * **Linux (Kali):**
        ```bash
        sudo apt update
        sudo apt install awscli
        ```
        *(Ensure Python 3 and pip are set up as well for general environment, though `awscli` usually handles its own Python dependencies.)*

2.  **Navigate to your desired download directory** (e.g., `~/Desktop/AI-Firewall/datasets`):
    ```bash
    cd ~/Desktop/AI-Firewall
    mkdir -p datasets
    cd datasets
    ```

3.  **Execute the AWS S3 Sync Command:**
    ```bash
    aws s3 sync --no-sign-request --region us-east-1 "s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/" ./CSE-CIC-IDS2018-Processed_CSVs
    ```
    * `--no-sign-request`: For public S3 bucket access without AWS credentials.
    * `--region us-east-1`: Recommended region.
    * `./CSE-CIC-IDS2018-Processed_CSVs`: Destination folder name.

**Note:** The full raw PCAP dataset is significantly larger (hundreds of GBs). The processed CSVs are more manageable (several GBs) and suitable for direct ML model training.

## Citation / Further Reading
If you use this dataset in research, please cite the original research paper:

Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, “Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization”, 4th International Conference on Information Systems Security and Privacy (ICISSP), Portugal, January 2018.
