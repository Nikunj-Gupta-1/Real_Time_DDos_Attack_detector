import pandas as pd
import numpy as np
import joblib
import sys
import warnings

# Suppress sklearn warnings
warnings.filterwarnings('ignore', message='X has feature names')
warnings.filterwarnings('ignore', message='X does not have valid feature names')

def predict_on_csv_enhanced(model_path, data_path):
    """
    Enhanced prediction script that handles binary model with multi-class test data
    Shows attack types while correctly evaluating binary classification performance
    """
    try:
        # Load the trained model
        print("Loading trained model...")
        model_data = joblib.load(model_path)
        
        # Load new data
        print(f"Loading data from {data_path}...")
        df = pd.read_csv(data_path)
        
        print(f"Data shape: {df.shape}")
        
        # Preprocess data
        print("Preprocessing data...")
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.fillna(0)
        
        # Handle labels for binary classification evaluation
        if ' Label' in df.columns:
            X = df.drop([' Label'], axis=1)
            y_true_original = df[' Label'].copy()  # Keep original attack types
            
            # Create binary labels for evaluation (BENIGN vs ATTACK)
            y_true_binary = y_true_original.apply(
                lambda x: 'BENIGN' if x == 'BENIGN' else 'ATTACK'
            )
            
            has_labels = True
            
            print(f"\nOriginal Dataset Composition:")
            original_counts = y_true_original.value_counts()
            benign_count = original_counts.get('BENIGN', 0)
            attack_count = len(y_true_original) - benign_count
            
            print(f"  BENIGN: {benign_count} samples")
            print(f"  ATTACK TYPES: {attack_count} samples")
            print(f"    Attack type breakdown:")
            for attack_type, count in original_counts.items():
                if attack_type != 'BENIGN':
                    print(f"      {attack_type}: {count} samples")
                    
        else:
            X = df
            has_labels = False
        
        # Remove non-numeric columns
        numeric_columns = X.select_dtypes(include=[np.number]).columns
        X = X[numeric_columns]
        
        # Ensure we have the same features as training
        feature_names = model_data['feature_names']
        missing_features = [f for f in feature_names if f not in X.columns]
        
        if missing_features:
            print(f"Warning: {len(missing_features)} features missing from data")
            for feature in missing_features:
                X[feature] = 0
        
        # Select only the features used in training
        X = X[feature_names]
        
        # Scale features using DataFrame to preserve feature names
        print("Scaling features...")
        X_df = pd.DataFrame(X, columns=feature_names)
        X_scaled = pd.DataFrame(
            model_data['scaler'].transform(X_df),
            columns=feature_names
        )
        
        # Make predictions
        print("Making predictions...")
        predictions = model_data['model'].predict(X_scaled)
        probabilities = model_data['model'].predict_proba(X_scaled)
        
        # Decode predictions
        predicted_labels = model_data['label_encoder'].inverse_transform(predictions)
        
        # Create comprehensive results dataframe
        results = pd.DataFrame({
            'Prediction': predicted_labels,
            'Confidence': np.max(probabilities, axis=1)
        })
        
        # Add true labels and evaluation metrics
        if has_labels:
            results['Original_Attack_Type'] = y_true_original.values
            results['True_Label_Binary'] = y_true_binary.values
            results['Correct_Binary_Classification'] = (results['Prediction'] == results['True_Label_Binary'])
            
            # Calculate binary classification accuracy
            accuracy = results['Correct_Binary_Classification'].mean()
            print(f"\n🎯 BINARY CLASSIFICATION PERFORMANCE")
            print(f"=" * 50)
            print(f"Overall Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
            
            # Detailed performance breakdown
            tp = len(results[(results['Prediction'] == 'ATTACK') & (results['True_Label_Binary'] == 'ATTACK')])
            tn = len(results[(results['Prediction'] == 'BENIGN') & (results['True_Label_Binary'] == 'BENIGN')])
            fp = len(results[(results['Prediction'] == 'ATTACK') & (results['True_Label_Binary'] == 'BENIGN')])
            fn = len(results[(results['Prediction'] == 'BENIGN') & (results['True_Label_Binary'] == 'ATTACK')])
            
            print(f"\nConfusion Matrix:")
            print(f"  True Positives (Correctly detected attacks): {tp}")
            print(f"  True Negatives (Correctly detected benign): {tn}")
            print(f"  False Positives (Benign classified as attack): {fp}")
            print(f"  False Negatives (Attacks missed): {fn}")
            
            # Calculate additional metrics
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            
            print(f"\nDetailed Metrics:")
            print(f"  Precision: {precision:.4f} ({precision*100:.2f}%)")
            print(f"  Recall: {recall:.4f} ({recall*100:.2f}%)")
            print(f"  F1-Score: {f1_score:.4f}")
        
        # Show prediction summary
        print(f"\n📊 PREDICTION SUMMARY")
        print(f"=" * 50)
        prediction_counts = results['Prediction'].value_counts()
        for pred_type, count in prediction_counts.items():
            percentage = (count / len(results)) * 100
            print(f"  {pred_type}: {count} samples ({percentage:.1f}%)")
        
        # Show detected attack types with confidence
        if has_labels:
            detected_attacks = results[results['Prediction'] == 'ATTACK']
            
            if len(detected_attacks) > 0:
                print(f"\n🚨 DETECTED ATTACK TYPES")
                print(f"=" * 50)
                
                # Group by original attack type
                attack_type_detection = detected_attacks.groupby('Original_Attack_Type').agg({
                    'Confidence': ['count', 'mean', 'min', 'max']
                }).round(4)
                
                attack_type_detection.columns = ['Count', 'Avg_Confidence', 'Min_Confidence', 'Max_Confidence']
                
                for attack_type in attack_type_detection.index:
                    stats = attack_type_detection.loc[attack_type]
                    print(f"  {attack_type}:")
                    print(f"    Detected: {int(stats['Count'])} samples")
                    print(f"    Avg Confidence: {stats['Avg_Confidence']:.4f}")
                    print(f"    Confidence Range: {stats['Min_Confidence']:.4f} - {stats['Max_Confidence']:.4f}")
                
                # Show high-confidence detections
                high_conf_attacks = detected_attacks[detected_attacks['Confidence'] > 0.9]
                if len(high_conf_attacks) > 0:
                    print(f"\n🔴 HIGH CONFIDENCE DETECTIONS (>90%)")
                    print(f"=" * 50)
                    high_conf_summary = high_conf_attacks['Original_Attack_Type'].value_counts()
                    for attack_type, count in high_conf_summary.items():
                        print(f"  {attack_type}: {count} high-confidence detections")
            
            # Show any missed attacks (false negatives)
            missed_attacks = results[results['Prediction'] == 'BENIGN'][results['True_Label_Binary'] == 'ATTACK']
            if len(missed_attacks) > 0:
                print(f"\n⚠️  MISSED ATTACKS (False Negatives)")
                print(f"=" * 50)
                missed_summary = missed_attacks['Original_Attack_Type'].value_counts()
                for attack_type, count in missed_summary.items():
                    avg_conf = missed_attacks[missed_attacks['Original_Attack_Type'] == attack_type]['Confidence'].mean()
                    print(f"  {attack_type}: {count} missed (avg confidence: {avg_conf:.4f})")
            
            # Show incorrectly flagged benign traffic (false positives)
            false_positives = results[(results['Prediction'] == 'ATTACK') & (results['True_Label_Binary'] == 'BENIGN')]
            if len(false_positives) > 0:
                print(f"\n🟡 FALSE POSITIVES (Benign classified as Attack)")
                print(f"=" * 50)
                avg_fp_conf = false_positives['Confidence'].mean()
                print(f"  Count: {len(false_positives)}")
                print(f"  Average Confidence: {avg_fp_conf:.4f}")
        
        # Save comprehensive results
        output_file = 'enhanced_prediction_results.csv'
        results.to_csv(output_file, index=False)
        print(f"\n💾 Results saved to {output_file}")
        
        # Generate summary report
        if has_labels:
            print(f"\n📋 SUMMARY REPORT")
            print(f"=" * 50)
            print(f"Model Performance: {'EXCELLENT' if accuracy > 0.95 else 'GOOD' if accuracy > 0.85 else 'NEEDS IMPROVEMENT'}")
            print(f"Attack Detection Rate: {recall*100:.1f}%")
            print(f"False Positive Rate: {(fp/(fp+tn)*100) if (fp+tn) > 0 else 0:.1f}%")
            print(f"Unique Attack Types Detected: {len(detected_attacks['Original_Attack_Type'].unique()) if len(detected_attacks) > 0 else 0}")
        
        return results
        
    except Exception as e:
        print(f"Error making predictions: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python enhanced_predict_ddos.py <model_path> <data_path>")
        print("Example: python enhanced_predict_ddos.py optimized_ddos_model.pkl random_sample.csv")
    else:
        model_path = sys.argv[1]
        data_path = sys.argv[2]
        predict_on_csv_enhanced(model_path, data_path)
