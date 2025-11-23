import pandas as pd
import sys
import os
import json

# Ensure the parent directory is in the path to import the merkle modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from Merkle_tree.merkle_ledger import ThreatLogEntry
from Merkle_tree.batched_ledger import BatchedThreatLogLedger

def main():
    # 1. Read the severity output CSV
    csv_path = "After_model/severity_output.csv"
    if not os.path.exists(csv_path):
        print(f"Error: {csv_path} not found. Please run severity.py first.")
        return

    print(f"Reading {csv_path}...")
    df = pd.read_csv(csv_path)

    # 2. Filter to exclude "Benign" entries
    # Check for 'mapped_label' or 'Attack_type' or 'Attack_encode' to filter
    # Based on severity.py, 'mapped_label' should be present
    if "mapped_label" in df.columns:
        attack_df = df[df["mapped_label"].str.lower() != "benign"]
    else:
        print("Warning: 'mapped_label' column not found. Attempting to filter by 'Attack_type' or 'Attack_encode'...")
        # Fallback logic if mapped_label is missing (though severity.py creates it)
        if "Attack_type" in df.columns:
             attack_df = df[df["Attack_type"].str.lower() != "benign"]
        else:
             print("Error: Could not determine attack label column.")
             return

    print(f"Total entries: {len(df)}")
    print(f"Attack entries to process: {len(attack_df)}")

    # 3. Initialize BatchedThreatLogLedger with batch size 10,000
    batch_size = 10000
    ledger = BatchedThreatLogLedger(batch_size=batch_size)

    # 4. Process entries and add to ledger
    count = 0
    for _, row in attack_df.iterrows():
        # Map fields
        # flow_id <- generated_id
        # attack_label <- mapped_label
        # severity <- severity
        
        flow_id = str(row.get("generated_id", ""))
        attack_label = str(row.get("mapped_label", "Unknown"))
        severity_score = float(row.get("severity", 0.0))
        
        # Create ThreatLogEntry
        entry = ThreatLogEntry.create(
            flow_id=flow_id,
            attack_label=attack_label,
            severity=severity_score
        )
        
        ledger.add_entry(entry)
        count += 1

    # Seal any remaining entries in the last batch
    ledger.seal_current_batch()

    # 5. Output results
    print(f"\nSuccessfully processed {count} attack entries.")
    print(f"Number of sealed batches: {len(ledger.sealed_batches)}")
    print(f"Number of blocks: {len(ledger.blocks)}")

    if ledger.blocks:
        last_block = ledger.blocks[-1]
        print("\n=== Latest Block Metadata ===")
        print(f"Block Index: {last_block.index}")
        print(f"Batch Merkle Root: {last_block.batch.merkle_root}")
        print(f"Batch Signature: {last_block.batch.signature}")
        
        # Verify the chain
        is_valid = ledger.verify_all()
        print(f"\nChain Integrity Verified: {is_valid}")
        
        # Save blockchain data to JSON
        # Get the project root directory (parent of Merkle_tree)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir)
        
        output_file = os.path.join(project_root, "blockchain_ledger.json")
        ledger_data = ledger.to_dict()
        with open(output_file, 'w') as f:
            json.dump(ledger_data, f, indent=2)
        print(f"\nBlockchain data saved to: {output_file}")
        
        # Also save a summary CSV with block information
        blocks_summary = []
        for block in ledger.blocks:
            blocks_summary.append({
                'block_index': block.index,
                'batch_id': block.batch.batch_id,
                'merkle_root': block.batch.merkle_root,
                'entry_count': block.batch.entry_count,
                'sealed_at': block.batch.sealed_at,
                'block_hash': block.block_hash,
                'prev_block_hash': block.prev_block_hash
            })
        
        blocks_df = pd.DataFrame(blocks_summary)
        blocks_csv = os.path.join(project_root, "blockchain_blocks_summary.csv")
        blocks_df.to_csv(blocks_csv, index=False)
        print(f"Blocks summary saved to: {blocks_csv}")
    else:
        print("\nNo blocks were created (maybe no attacks found?).")

if __name__ == "__main__":
    main()
