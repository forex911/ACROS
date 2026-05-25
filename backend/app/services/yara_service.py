import os
import yara
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

class YaraService:
    """
    Service to compile and scan files using YARA signatures.
    """
    def __init__(self, rules_dir: str = None):
        if rules_dir is None:
            self.rules_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), 'sandbox', 'yara_rules')
        else:
            self.rules_dir = rules_dir
            
        self.rules = None
        self._load_rules()

    def _load_rules(self):
        """
        Dynamically loads and compiles all .yar or .yara files from the rules directory.
        """
        if not os.path.exists(self.rules_dir):
            logger.warning(f"YARA rules directory {self.rules_dir} does not exist.")
            return

        rule_files = {}
        try:
            for root, _, files in os.walk(self.rules_dir):
                for file in files:
                    if file.endswith('.yar') or file.endswith('.yara'):
                        rule_path = os.path.join(root, file)
                        rule_files[file] = rule_path
            
            if rule_files:
                self.rules = yara.compile(filepaths=rule_files)
                logger.info(f"Compiled {len(rule_files)} YARA rule files successfully.")
            else:
                logger.info("No YARA rules found to compile.")
        except yara.SyntaxError as e:
            logger.error(f"Syntax error compiling YARA rules: {e}")
        except Exception as e:
            logger.error(f"Unexpected error loading YARA rules: {e}")

    def scan_file(self, file_path: str) -> List[Dict]:
        """
        Scans a file against compiled YARA rules.
        """
        matches_result = []
        if not self.rules:
            logger.warning("No YARA rules loaded for scanning.")
            return matches_result

        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File to scan not found: {file_path}")
                
            matches = self.rules.match(file_path)
            
            for match in matches:
                matches_result.append({
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": match.tags,
                    "meta": match.meta
                })
        except Exception as e:
            logger.error(f"Error scanning file {file_path} with YARA: {e}")
            
        return matches_result
