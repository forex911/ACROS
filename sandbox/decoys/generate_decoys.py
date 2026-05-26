import os
import shutil
import logging

logger = logging.getLogger("decoy_generator")

def generate_decoys(sandbox_dir: str):
    """
    Populates the sandbox environment with fake documents, browser history,
    and credentials to encourage malware to detonate fully.
    """
    try:
        docs_dir = os.path.join(sandbox_dir, "Documents")
        os.makedirs(docs_dir, exist_ok=True)
        
        with open(os.path.join(docs_dir, "passwords.txt"), "w") as f:
            f.write("Admin: Password123!\nBanking: 5932-1234\n")
            
        with open(os.path.join(docs_dir, "Q4_Financials.pdf"), "wb") as f:
            f.write(b"%PDF-1.4\n%FAKE_PDF_CONTENT")
            
        # Create fake browser history
        appdata_dir = os.path.join(sandbox_dir, "AppData", "Local", "Google", "Chrome", "User Data", "Default")
        os.makedirs(appdata_dir, exist_ok=True)
        with open(os.path.join(appdata_dir, "History"), "w") as f:
            f.write("SQLITE FORMAT 3...\n") # Mock sqlite header
            
        logger.info("Successfully generated sandbox decoys.")
    except Exception as e:
        logger.error(f"Failed to generate decoys: {e}")

if __name__ == "__main__":
    sandbox_path = os.environ.get("SANDBOX_DIR", "/tmp/sandbox")
    generate_decoys(sandbox_path)
