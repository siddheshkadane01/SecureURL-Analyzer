import pandas as pd
import os

def load_dataset(filename="dataset.csv"):
    """
    Loads the synthetic dataset into a Pandas DataFrame.
    """
    if not os.path.exists(filename):
        raise FileNotFoundError(f"Dataset {filename} not found. Please run generate_dataset.py first.")
    
    df = pd.DataFrame(pd.read_csv(filename))
    
    # Target variable 'is_phishing' is the last column
    X = df.drop('is_phishing', axis=1)
    y = df['is_phishing']
    
    return X, y
