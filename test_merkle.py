from merkle_ledger import ThreatLogEntry, MerkleTree
from batched_ledger import BatchedThreatLogLedger

def main():
    ledger = BatchedThreatLogLedger(batch_size=50)

    for i in range(55):
        # Updated to use the new create signature and float severity
        entry = ThreatLogEntry.create(
            flow_id=f"flow_{i}",
            attack_label="DoS",
            severity=0.8 + (i % 20) / 100.0,
            src_ip=f"10.0.0.{i%5 + 1}",
            dst_ip="192.168.0.10",
            action="BLOCK",
        )
        ledger.add_entry(entry)

    print("Open entries (current batch, not sealed yet):", len(ledger.open_entries))
    print("Number of sealed batches:", len(ledger.sealed_batches))
    print("Number of blocks:", len(ledger.blocks))

    print("\n=== Public RSA key (PEM) ===")
    print(ledger.public_key_pem)

    if ledger.blocks:
        print("\n=== First block metadata ===")
        first_block = ledger.blocks[0]
        print(first_block.to_dict())

        print("\nBatch Merkle root (from block):", first_block.batch.merkle_root)
        print("Batch signature (base64):", first_block.batch.signature)

        batch_entries = ledger.sealed_batches[0]
        tree = MerkleTree.from_entries(batch_entries)

        print("\n=== Merkle tree levels for batch 1 ===")
        for depth, level in enumerate(tree.levels):
            print(f"Level {depth}:")
            for h in level:
                print("  ", h)

        print("\nVerify batch 0 integrity:", ledger.verify_batch_integrity(0))
        print("Verify whole block chain:", ledger.verify_block_chain())
        print("Verify all (batches + chain):", ledger.verify_all())

        print("\nTampering with one entry in sealed batch...")
        batch_entries[0].attack_label = "Normal"
        print("Verify batch 0 integrity after tampering:", ledger.verify_batch_integrity(0))
        print("Verify all after tampering:", ledger.verify_all())

if __name__ == "__main__":
    main()


'''
from merkle_ledger import ThreatLogEntry, ThreatLogLedger


class IntrusionTriageEngine:
    def __init__(self, model, feature_columns, malicious_label=1, threshold=None):
        self.model = model
        self.feature_columns = feature_columns
        self.malicious_label = malicious_label
        self.threshold = threshold
        self.ledger = ThreatLogLedger()

    def _compute_severity(self, flow_row, malicious_score):
        if malicious_score is not None:
            base = int(round(malicious_score * 100))
        else:
            base = 80
        return max(0, min(100, base))

    def _select_action(self, flow_row, severity):
        if severity >= 80:
            return "BLOCK"
        if severity >= 50:
            return "QUARANTINE"
        return "ALERT"

    def predict_flow(self, flow_row, meta):
        X = flow_row[self.feature_columns].values.reshape(1, -1)
        malicious_score = None
        if self.threshold is not None and hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(X)[0]
            malicious_score = float(proba[self.malicious_label])
            is_malicious = malicious_score >= self.threshold
        else:
            y_pred = self.model.predict(X)[0]
            is_malicious = y_pred == self.malicious_label
        if is_malicious:
            severity = self._compute_severity(flow_row, malicious_score)
            action = self._select_action(flow_row, severity)
            entry = ThreatLogEntry.create(
                flow_id=str(meta.get("flow_id", "")),
                src_ip=str(meta.get("src_ip", "")),
                dst_ip=str(meta.get("dst_ip", "")),
                attack_label=str(meta.get("attack_label", "intrusion")),
                severity=severity,
                action=action,
            )
            self.ledger.add_entry(entry)
        else:
            severity = 0
            action = "NONE"
        return {
            "is_malicious": bool(is_malicious),
            "malicious_score": malicious_score,
            "severity": severity,
            "action": action,
        }

    def process_dataframe(self, df, meta_config=None):
        results = []
        for idx, row in df.iterrows():
            meta = {}
            if meta_config:
                for key, col in meta_config.items():
                    meta[key] = row.get(col, "")
            meta.setdefault("flow_id", idx)
            r = self.predict_flow(row, meta)
            results.append(r)
        return results

    def compute_merkle_root(self):
        return self.ledger.compute_merkle_root()

    def verify_ledger(self):
        return self.ledger.verify_integrity()

    def get_ledger_snapshot(self):
        return self.ledger.snapshot()

    def get_entries(self):
        return self.ledger.get_entries()
'''