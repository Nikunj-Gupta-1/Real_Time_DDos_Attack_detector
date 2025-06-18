import pandas as pd
import numpy as np
import os

def fetch_random_records_fixed(file_path, num_records=100, output_file='random_sample.csv'):
    """
    Fixed version: Fetch random records from the original CIC-DDoS2019 dataset
    """
    
    print(f"🔄 Fetching {num_records} random records from {file_path}")
    
    # Check if file exists
    if not os.path.exists(file_path):
        print(f"❌ Error: File {file_path} not found!")
        return None
    
    try:
        # Get total number of rows in the file (excluding header)
        print("📊 Counting total records...")
        total_rows = sum(1 for line in open(file_path)) - 1  # Subtract 1 for header
        print(f"   Total records in dataset: {total_rows:,}")
        
        # Generate random row indices
        if num_records > total_rows:
            print(f"⚠️  Requested {num_records} records, but dataset only has {total_rows}")
            num_records = total_rows
        
        # Create random indices (fix: ensure proper array handling)
        random_indices = np.random.choice(total_rows, size=num_records, replace=False)
        
        # Fix: Convert to list and add 1 properly
        random_row_numbers = [idx + 1 for idx in random_indices]  # Convert to 1-based indexing
        
        print(f"🎲 Generated {len(random_row_numbers)} random indices")
        
        # Create skip_rows set properly
        all_rows = set(range(1, total_rows + 1))  # All row numbers (1-based)
        rows_to_keep = set(random_row_numbers)    # Rows we want to keep
        skip_rows = all_rows - rows_to_keep       # Rows to skip
        
        print("📖 Reading random records...")
        df_sample = pd.read_csv(file_path, skiprows=list(skip_rows))
        
        # Verify we got the right number of records
        print(f"✅ Successfully fetched {len(df_sample)} records")
        
        # Display sample information
        print(f"\n📈 Sample Overview:")
        print(f"   Shape: {df_sample.shape}")
        
        if ' Label' in df_sample.columns:
            label_counts = df_sample[' Label'].value_counts()
            print(f"   Label distribution:")
            for label, count in label_counts.items():
                percentage = (count / len(df_sample)) * 100
                print(f"     {label}: {count} records ({percentage:.1f}%)")
        
        # Save to file
        df_sample.to_csv(output_file, index=False)
        print(f"💾 Random sample saved to: {output_file}")
        
        return df_sample
        
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return None


# Usage example
if __name__ == "__main__":
    # Replace with your actual file path
    original_file = 'CIC_DDoS2019_balanced_reduced.csv'  # Your 28GB combined file
    
    # Fetch 100 random records
    sample_df = fetch_random_records_fixed(original_file, num_records=100)
    
    if sample_df is not None:
        print("\n🎉 Random sampling completed successfully!")
        print("First 5 records:")
        print(sample_df.head())
