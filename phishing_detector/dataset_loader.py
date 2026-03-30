import pandas as pd
import os

def load_dataset(filename="Dataset1.csv"):
    """
    Loads the synthetic dataset into a Pandas DataFrame.
    """
    if not os.path.exists(filename):
        raise FileNotFoundError(f"Dataset {filename} not found.")
    
    df = pd.DataFrame(pd.read_csv(filename))
    
    # Target variable 'Type' is the label (0 = Legitimate, 1 = Phishing)
    # We select the top 12 features that our extractor knows how to parse:
    top_features = [
        'url_length', 'entropy_of_domain', 'average_subdomain_length', 
        'domain_length', 'entropy_of_url', 'number_of_subdomains', 
        'number_of_digits_in_domain', 'number_of_dots_in_url', 
        'number_of_digits_in_url', 'number_of_slash_in_url', 
        'number_of_special_char_in_url', 'path_length'
    ]
    
    X = df[top_features]
    y = df['Type']
    
    return X, y
