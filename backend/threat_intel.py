import json
from pathlib import Path


class ThreatIntelEngine:
    """Loads and queries the local, offline CISA KEV / CVE threat intelligence
    cache. No network access required."""

    def __init__(self):
        self.records: list[dict] = []
        self._load_cache()

    def _load_cache(self):
        data_path = Path(__file__).parent / 'cisa_kev_cache.json'
        if data_path.exists():
            with open(data_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.records = data.get('vulnerabilities', [])

    def query(self, subsystem: str = None, syscall: str = None,
              capability: str = None, module: str = None) -> list[dict]:
        """Query threat records by kernel component. Returns relevance-ranked
        results with match reasoning."""
        results = []
        for record in self.records:
            match_reasons = []
            if subsystem and subsystem in record.get('kernelSubsystem', ''):
                match_reasons.append(f"Subsystem match: {subsystem}")
            if syscall and syscall in record.get('relatedSyscalls', []):
                match_reasons.append(f"Syscall match: {syscall}")
            if capability and capability in record.get('relatedCapabilities', []):
                match_reasons.append(f"Capability match: {capability}")
            if module and module in record.get('relatedModules', []):
                match_reasons.append(f"Module match: {module}")

            if match_reasons:
                record_copy = dict(record)
                record_copy['match_reason'] = "; ".join(match_reasons)
                record_copy['source_label'] = 'CISA KEV' if record.get('cisaKEV') else 'NVD'
                results.append(record_copy)

        return sorted(results, key=lambda x: len(x['match_reason']), reverse=True)

    def get_all(self) -> list[dict]:
        return self.records

    def get_relevant_for_profile(self, profile: dict) -> list[dict]:
        """Find all threat records relevant to a workload profile by
        cross-referencing observed syscalls, capabilities, and modules."""
        results = []
        syscall_counts = profile.get('syscall_counts', {})
        loaded_modules = profile.get('loaded_modules', [])

        for record in self.records:
            relevant = False
            relevance_level = "LOW"

            if any(sc in syscall_counts for sc in record.get('relatedSyscalls', [])):
                relevant = True
                relevance_level = "HIGH"
            elif any(mod in loaded_modules for mod in record.get('relatedModules', [])):
                relevant = True
                relevance_level = "HIGH"
            elif record.get('kernelSubsystem'):
                relevant = True
                relevance_level = "MEDIUM"

            if relevant:
                record_copy = dict(record)
                record_copy['runtime_relevance'] = relevance_level
                results.append(record_copy)

        return results
