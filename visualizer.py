import json
import matplotlib.pyplot as plt
import seaborn as sns
import os

def plot_results(results_filepath="results/accuracy_vs_n.json", output_filepath="results/accuracy_plot.png"):
    # Load results
    print(f"Loading results from {results_filepath}...")
    with open(results_filepath, "r") as f:
        results = json.load(f)
        
    # Convert string keys to int and sort
    n_values = sorted([int(k) for k in results.keys()])
    accuracies = [results[str(k)] * 100 for k in n_values]  # Convert to percentage
    
    # Plotting
    sns.set_theme(style="whitegrid")
    plt.figure(figsize=(10, 6))
    
    plt.plot(n_values, accuracies, marker='o', linewidth=2.5, markersize=8, color='#2c3e50')
    
    plt.title('Encrypted Traffic Classification Accuracy vs. Number of Packets', fontsize=14, pad=15)
    plt.xlabel('Number of Initial Packets Analyzed (N)', fontsize=12)
    plt.ylabel('Accuracy (%)', fontsize=12)
    
    # Add data labels
    for i, txt in enumerate(accuracies):
        plt.annotate(f"{txt:.1f}%", (n_values[i], accuracies[i]), 
                     textcoords="offset points", xytext=(0,10), ha='center', fontsize=10)
        
    plt.ylim(0, 105)
    plt.xticks(n_values)
    
    plt.tight_layout()
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(output_filepath), exist_ok=True)
    plt.savefig(output_filepath, dpi=300)
    print(f"Plot saved successfully to {output_filepath}")

if __name__ == "__main__":
    os.chdir("C:/Users/CHATRADHARA/.gemini/antigravity/scratch/traffic_classifier")
    plot_results()
