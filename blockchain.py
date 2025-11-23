import streamlit as st
import pandas as pd
import json
import os
import sys
from pathlib import Path
import graphviz
from typing import List, Optional
import io

ROOT = Path(__file__).resolve().parent.parent  # Project root
ALT = ROOT  # Use project root instead of /mnt/data
UPLOAD_DIR = ALT / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# Make sure your merkle module is importable
if str(ROOT / "Merkle_tree") not in sys.path:
    sys.path.append(str(ROOT / "Merkle_tree"))

# Import your Merkle utilities
try:
    from merkle_ledger import MerkleTree, ThreatLogEntry, sha256_hex
except Exception as e:
    st.warning("Could not import merkle_ledger module. Make sure merkle_ledger.py is in the same folder.")
    st.stop()

st.set_page_config(page_title="Blockchain Demo (Sidebar Nav)", layout="wide")
st.title("🔐 Blockchain & IDS Demo")

# ----------------- Utility: safe timestamp parsing -----------------
def parse_timestamp_safe(ts) -> Optional[object]:
    """
    Accepts: None, empty, string, pandas.Timestamp, datetime.
    Returns: datetime (python) or None.
    """
    if ts is None:
        return None
    try:
        if pd.isna(ts):
            return None
    except Exception:
        pass
    if hasattr(ts, "isoformat"):
        return ts
    if isinstance(ts, pd.Timestamp):
        try:
            return ts.to_pydatetime()
        except Exception:
            return None
    if isinstance(ts, str):
        s = ts.strip()
        if s == "":
            return None
        try:
            return pd.to_datetime(s).to_pydatetime()
        except Exception:
            return None
    return None

def df_to_entries_safe(df: pd.DataFrame) -> List[ThreatLogEntry]:
    entries = []
    for _, r in df.iterrows():
        ts_parsed = parse_timestamp_safe(r.get("timestamp", None))
        try:
            entry = ThreatLogEntry.create(
                flow_id=str(r.get("flow_id", "")),
                attack_label=str(r.get("attack_label", "")),
                severity=float(r.get("severity", 0.0)) if pd.notna(r.get("severity", None)) else 0.0,
                src_ip=str(r.get("src_ip", "")),
                dst_ip=str(r.get("dst_ip", "")),
                action=str(r.get("action", "")),
                timestamp=ts_parsed
            )
        except Exception as e:
            st.error(f"Failed to create ThreatLogEntry for row {_}: {e}")
            raise
        entries.append(entry)
    return entries

# ----------------- Sidebar navigation -----------------
page = st.sidebar.radio("📑 Pages", ["Merkle Playground", "Upload Logs", "Blockchain Explorer"])

# ----------------- Page 1: Merkle Playground -----------------
if page == "Merkle Playground":
    st.header("🌳 Merkle Playground")
    st.write("Edit a small set of logs, build a Merkle tree, then verify to detect tampering.")
    
    n_leaves = st.slider("Number of leaves", min_value=4, max_value=16, value=8)

    def make_sample(i):
        e = ThreatLogEntry.create(
            flow_id=f"flow_{i+1}",
            attack_label="Benign" if i % 3 == 0 else "DoS Hulk" if i % 3 == 1 else "PortScan",
            severity=round(0.1 + (i % 10) * 0.07, 2),
            src_ip=f"10.0.0.{(i % 6) + 1}",
            dst_ip=f"192.168.0.{(i % 10) + 1}",
            action="",
        )
        return {
            "timestamp": e.timestamp,
            "flow_id": e.flow_id,
            "attack_label": e.attack_label,
            "severity": e.severity,
            "src_ip": e.src_ip,
            "dst_ip": e.dst_ip,
            "action": e.action,
        }

    # Init dataset
    if "merkle_df" not in st.session_state:
        st.session_state.merkle_df = pd.DataFrame([make_sample(i) for i in range(n_leaves)])

    if len(st.session_state.merkle_df) != n_leaves:
        st.session_state.merkle_df = pd.DataFrame([make_sample(i) for i in range(n_leaves)])

    try:
        orig_entries = df_to_entries_safe(st.session_state.merkle_df)
    except Exception:
        st.error("Error converting rows to ThreatLogEntry.")
        st.stop()

    orig_leaf_hashes = [sha256_hex(e.to_canonical_string()) for e in orig_entries]
    orig_tree = MerkleTree([e.to_canonical_string() for e in orig_entries])

    # ---------------- GRAPH FIRST ----------------
    st.markdown("### 🌲 Merkle Tree Visualization")
    try:
        dot = graphviz.Digraph()
        dot.attr(rankdir="TB", size="14,10")
        dot.attr("node", style="filled", fontname="Helvetica", fontsize="11")
        dot.attr("edge", penwidth="2.5", color="#555555")

        levels = orig_tree.levels
        colors = ["#90EE90", "#87CEEB", "#FFB6C1", "#FFA07A", "#FF6B6B"]

        for lvl_idx, level in enumerate(levels):
            color = colors[min(lvl_idx, len(colors) - 1)]
            for pos, h in enumerate(level):
                node = f"n_{lvl_idx}_{pos}"
                label = f"{h[:12]}...\\nLevel {lvl_idx} | Pos {pos}"

                if lvl_idx == len(levels) - 1:
                    dot.node(
                        node,
                        label=label,
                        shape="box",
                        fillcolor="#FF4444",
                        fontcolor="white",
                        penwidth="4",
                        style="filled,bold",
                    )
                else:
                    dot.node(node, label=label, shape="box", fillcolor=color, fontcolor="#333333", penwidth="2")

        for lvl_idx in range(len(levels) - 1):
            for pos in range(len(levels[lvl_idx])):
                dot.edge(
                    f"n_{lvl_idx}_{pos}",
                    f"n_{lvl_idx+1}_{pos//2}",
                    color=colors[min(lvl_idx + 1, len(colors) - 1)],
                )

        st.graphviz_chart(dot, use_container_width=True)

    except Exception as e:
        st.warning(f"Tree visualization failed: {e}")
        st.write("Levels:", orig_tree.levels)

    # ---------------- ROOT AFTER GRAPH ----------------
    st.markdown("### 🔑 Original Merkle Root")
    st.code(orig_tree.root, language="text")

    # ---------------- EDIT TABLE BELOW GRAPH ----------------
    st.markdown("### ✏️ Edit Entries")
    edited = st.data_editor(
        st.session_state.merkle_df,
        num_rows="dynamic",
        use_container_width=True,
        key="editor",
    )

    # ---------------- SUMMARY ----------------
    st.markdown("### 📊 Summary")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Leaves", len(orig_entries))
    with col2:
        st.metric("Tree Depth", len(orig_tree.levels))
    with col3:
        st.metric("Root Hash (short)", orig_tree.root[:16] + "...")

    st.markdown("---")

    # ---------------- VERIFICATION ----------------
    if st.button("🔍 Verify Edits", type="primary"):

        try:
            new_entries = df_to_entries_safe(edited)
        except Exception:
            st.error("Invalid timestamps or formatting.")
            st.stop()

        new_hashes = [sha256_hex(e.to_canonical_string()) for e in new_entries]
        new_tree = MerkleTree([e.to_canonical_string() for e in new_entries])
        tampered = new_tree.root != orig_tree.root

        changed = [i for i, (a, b) in enumerate(zip(orig_leaf_hashes, new_hashes)) if a != b]

        col1, col2 = st.columns(2)
        with col1:
            st.write("**Original root:**")
            st.code(orig_tree.root)
        with col2:
            st.write("**New root:**")
            st.code(new_tree.root)

        if tampered:
            st.error(f"⚠️ TAMPERED — Changed leaf indices: {changed}")

            highlighted = edited.copy()
            highlighted["_tampered"] = ["✓ YES" if i in changed else "" for i in range(len(highlighted))]

            st.dataframe(
                highlighted.style.apply(
                    lambda row: [
                        "background-color: #ffdddd" if row.name in changed else "" for _ in row
                    ],
                    axis=1,
                ),
                use_container_width=True,
            )

        else:
            st.success("✅ No tampering detected. Roots match!")
            st.dataframe(edited, use_container_width=True)

# ----------------- Page 2: Upload -----------------
elif page == "Upload Logs":
    st.header("📤 Upload Logs")
    st.write("Upload a logs file and it will be saved to the uploads folder.")
    
    upload = st.file_uploader("Upload CSV or JSON logs", type=["csv", "json", "txt"], accept_multiple_files=False)
    if upload is not None:
        save_path = UPLOAD_DIR / upload.name
        with open(save_path, "wb") as f:
            f.write(upload.getbuffer())
        st.success(f"✅ Saved upload to: `{save_path}`")
        st.info("💡 Use Explorer or Merkle Playground to work with this file later.")

# ----------------- Page 3: Explorer -----------------
elif page == "Blockchain Explorer":
    st.header("🔍 Blockchain Explorer")
    
    ledger_path = ALT / "blockchain_ledger.json"
    summary_csv = ALT / "blockchain_blocks_summary.csv"
    
    if not ledger_path.exists():
        st.warning(f"⚠️ No ledger found at `{ledger_path.name}`. You can upload one below.")
        uploaded_ledger = st.file_uploader("Upload ledger JSON", type=["json"], key="ledger_upload")
        if uploaded_ledger is not None:
            try:
                ledger_json = json.load(uploaded_ledger)
                with open(ledger_path, "w", encoding="utf-8") as f:
                    json.dump(ledger_json, f, indent=2)
                st.success(f"✅ Ledger saved to {ledger_path}")
                st.rerun()
            except Exception as e:
                st.error(f"❌ Failed to save ledger: {e}")
    else:
        try:
            with open(ledger_path, "r", encoding="utf-8") as f:
                ledger = json.load(f)
            blocks = ledger.get("blocks", [])
            
            if not blocks:
                st.info("ℹ️ Ledger exists but contains no blocks.")
            else:
                # Blocks table
                rows = []
                for b in blocks:
                    idx = b.get("index")
                    batch = b.get("batch", {})
                    rows.append({
                        "Index": idx,
                        "Batch ID": batch.get("batch_id"),
                        "Merkle Root": batch.get("merkle_root", "")[:16] + "...",
                        "Entries": batch.get("entry_count"),
                        "Sealed At": b.get("created_at"),
                        "Block Hash": b.get("block_hash", "")[:16] + "...",
                    })
                
                df_blocks = pd.DataFrame(rows)
                st.markdown("### 📦 Blocks")
                st.dataframe(df_blocks, use_container_width=True)
                
                # Chain validation
                st.markdown("### ✅ Chain Validation")
                validity = []
                last_hash = ""
                chain_ok = True

                def batch_dict_to_canonical(batch: dict) -> str:
                    # Reconstruct the same canonical string used by Block.create -> MerkleBatch.to_canonical_string
                    # Note: batch dict fields must match the names used when the ledger was saved.
                    return "|".join(
                        [
                            str(batch.get("batch_id", "")),
                            str(batch.get("sealed_at", "")),
                            str(batch.get("merkle_root", "")),
                            str(batch.get("entry_count", "")),
                            str(batch.get("signature", "")),
                        ]
                    )

                for b in blocks:
                    batch = b.get("batch", {})
                    # Recreate canonical header exactly as Block.create does:
                    header = "|".join(
                        [
                            str(b.get("index")),
                            batch_dict_to_canonical(batch),
                            str(b.get("prev_block_hash", "")),
                            str(b.get("created_at", "")),
                        ]
                    )
                    expected_hash = sha256_hex(header)
                    ok = expected_hash == b.get("block_hash")
                    prev_ok = (b.get("prev_block_hash") == last_hash) if last_hash != "" else True
                    validity.append({
                        "Index": b.get("index"),
                        "Hash Valid": "✅" if ok else "❌",
                        "Prev Link Valid": "✅" if prev_ok else "❌"
                    })
                    last_hash = b.get("block_hash")
                    if not ok or not prev_ok:
                        chain_ok = False

                if chain_ok:
                    st.success("✅ Chain is valid!")
                else:
                    st.error("❌ Chain integrity compromised!")

                st.dataframe(pd.DataFrame(validity), use_container_width=True)
                
                
                # Block viewer
                st.markdown("### 🔎 Block Viewer")
                idx_choice = st.number_input("Block index to view", min_value=1, max_value=len(blocks), value=1, step=1)
                chosen = next((b for b in blocks if b.get("index") == int(idx_choice)), None)
                
                if chosen:
                    st.json(chosen)
                    
                    pub = ledger.get("public_key_pem")
                    if pub:
                        with st.expander("🔐 Public Key (PEM)"):
                            st.code(pub, language="text")
                    
                    if st.button("💾 Download this block JSON"):
                        st.download_button(
                            "Download block",
                            data=json.dumps(chosen, indent=2),
                            file_name=f"block_{chosen.get('index')}.json",
                            mime="application/json"
                        )
        except Exception as e:
            st.error(f"❌ Failed to read ledger: {e}")
    
    # Summary CSV
    if summary_csv.exists():
        st.markdown("---")
        st.markdown("### 📊 Blocks Summary CSV")
        try:
            df_summary = pd.read_csv(summary_csv)
            st.dataframe(df_summary.head(200), use_container_width=True)
            
            if st.button("💾 Download blocks summary CSV"):
                with open(summary_csv, "rb") as f:
                    st.download_button(
                        "Download summary CSV",
                        data=f,
                        file_name="blockchain_blocks_summary.csv",
                        mime="text/csv"
                    )
        except Exception as e:
            st.error(f"❌ Failed to read summary CSV: {e}")