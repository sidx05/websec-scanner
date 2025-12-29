"""
Static file metadata analyzer for security assessment.

Analyzes file metadata WITHOUT executing any code (safe, legal analysis).
Supports: PE executables, PDFs, Office docs, images, archives.
"""

import hashlib
import struct
from pathlib import Path
from typing import Dict, List, Optional
import re


class FileAnalyzer:
    """Static file metadata and security property analyzer."""
    
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.metadata: Dict = {}
        self.alerts: List[str] = []
    
    def analyze(self) -> Dict:
        """
        Perform comprehensive static analysis.
        
        Returns:
            Dictionary with metadata, hashes, and security findings
        """
        if not self.file_path.exists():
            return {'error': 'File not found'}
        
        result = {
            'filename': self.file_path.name,
            'size_bytes': self.file_path.stat().st_size,
            'extension': self.file_path.suffix.lower(),
            'hashes': self._compute_hashes(),
            'file_type': 'unknown',
            'alerts': [],
        }
        
        # Determine file type by magic bytes
        file_type = self._detect_file_type()
        result['file_type'] = file_type
        
        # Type-specific analysis
        if file_type == 'PE':
            result['pe_metadata'] = self._analyze_pe()
        elif file_type == 'PDF':
            result['pdf_metadata'] = self._analyze_pdf()
        elif file_type == 'ZIP':
            result['archive_metadata'] = self._analyze_archive()
        elif file_type.startswith('image'):
            result['image_metadata'] = self._analyze_image()
        
        # Generic suspicious pattern checks
        result['suspicious_patterns'] = self._check_suspicious_patterns()
        
        # Entropy check (packed/encrypted files)
        result['entropy'] = self._calculate_entropy()
        if result['entropy'] > 7.5:
            self.alerts.append('High entropy (possible packing/encryption)')
        
        result['alerts'] = self.alerts
        return result
    
    def _compute_hashes(self) -> Dict[str, str]:
        """Compute MD5, SHA1, SHA256 hashes."""
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        
        with self.file_path.open('rb') as f:
            while chunk := f.read(8192):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
        
        return {
            'md5': md5.hexdigest(),
            'sha1': sha1.hexdigest(),
            'sha256': sha256.hexdigest(),
        }
    
    def _detect_file_type(self) -> str:
        """Detect file type by magic bytes."""
        with self.file_path.open('rb') as f:
            header = f.read(20)
        
        if header.startswith(b'MZ'):
            return 'PE'
        elif header.startswith(b'%PDF'):
            return 'PDF'
        elif header.startswith(b'PK\x03\x04'):
            return 'ZIP'
        elif header.startswith(b'\x89PNG'):
            return 'image/png'
        elif header.startswith(b'\xff\xd8\xff'):
            return 'image/jpeg'
        elif header.startswith(b'GIF8'):
            return 'image/gif'
        elif header.startswith(b'\x1f\x8b'):
            return 'GZIP'
        elif header.startswith(b'Rar!'):
            return 'RAR'
        
        return 'unknown'
    
    def _analyze_pe(self) -> Dict:
        """Analyze PE (Windows executable) metadata."""
        pe_info = {'format': 'PE/COFF'}
        
        try:
            with self.file_path.open('rb') as f:
                # DOS header
                f.seek(0x3c)
                pe_offset = struct.unpack('<I', f.read(4))[0]
                
                # PE signature
                f.seek(pe_offset)
                sig = f.read(4)
                if sig != b'PE\x00\x00':
                    self.alerts.append('Invalid PE signature')
                    return pe_info
                
                # COFF header
                machine = struct.unpack('<H', f.read(2))[0]
                sections = struct.unpack('<H', f.read(2))[0]
                timestamp = struct.unpack('<I', f.read(4))[0]
                
                pe_info['machine'] = {0x14c: 'x86', 0x8664: 'x64'}.get(machine, hex(machine))
                pe_info['sections'] = sections
                pe_info['compile_timestamp'] = timestamp
                
                # Optional header (characteristics)
                f.seek(pe_offset + 0x18)
                optional_magic = struct.unpack('<H', f.read(2))[0]
                pe_info['bitness'] = '32-bit' if optional_magic == 0x10b else '64-bit'
                
                # Check for suspicious characteristics
                if sections > 20:
                    self.alerts.append(f'Unusually high section count: {sections}')
                
        except Exception as e:
            self.alerts.append(f'PE parsing error: {e}')
        
        return pe_info
    
    def _analyze_pdf(self) -> Dict:
        """Analyze PDF metadata and structure."""
        pdf_info = {}
        
        try:
            with self.file_path.open('rb') as f:
                content = f.read(10000)  # Read first 10KB
            
            text = content.decode('latin-1', errors='ignore')
            
            # PDF version
            version_match = re.search(r'%PDF-(\d+\.\d+)', text)
            if version_match:
                pdf_info['version'] = version_match.group(1)
            
            # Check for suspicious elements
            suspicious_keywords = [
                '/JavaScript', '/JS', '/Launch', '/OpenAction',
                '/AA', '/AcroForm', '/EmbeddedFile'
            ]
            
            found_suspicious = []
            for keyword in suspicious_keywords:
                if keyword in text:
                    found_suspicious.append(keyword)
            
            if found_suspicious:
                self.alerts.append(f'Suspicious PDF features: {", ".join(found_suspicious)}')
                pdf_info['suspicious_features'] = found_suspicious
        
        except Exception as e:
            self.alerts.append(f'PDF parsing error: {e}')
        
        return pdf_info
    
    def _analyze_archive(self) -> Dict:
        """Analyze archive metadata."""
        archive_info = {'type': 'archive'}
        
        # Count files and check for nested archives (zip bombs)
        try:
            import zipfile
            if zipfile.is_zipfile(self.file_path):
                with zipfile.ZipFile(self.file_path, 'r') as zf:
                    file_list = zf.namelist()
                    archive_info['file_count'] = len(file_list)
                    
                    # Check for nested archives
                    nested = [f for f in file_list if f.endswith(('.zip', '.rar', '.7z'))]
                    if nested:
                        self.alerts.append(f'Nested archives detected: {len(nested)}')
                    
                    # Check compression ratio (zip bomb detection)
                    total_compressed = sum(zf.getinfo(f).compress_size for f in file_list)
                    total_uncompressed = sum(zf.getinfo(f).file_size for f in file_list)
                    
                    if total_compressed > 0:
                        ratio = total_uncompressed / total_compressed
                        archive_info['compression_ratio'] = round(ratio, 2)
                        
                        if ratio > 100:
                            self.alerts.append(f'Extreme compression ratio: {ratio:.0f}x (possible zip bomb)')
        
        except Exception as e:
            self.alerts.append(f'Archive parsing error: {e}')
        
        return archive_info
    
    def _analyze_image(self) -> Dict:
        """Analyze image metadata."""
        img_info = {}
        
        try:
            # Check for EXIF data (potential privacy leak)
            with self.file_path.open('rb') as f:
                data = f.read(1000)
            
            if b'Exif' in data:
                self.alerts.append('EXIF metadata present (may contain GPS/device info)')
                img_info['has_exif'] = True
        
        except Exception:
            pass
        
        return img_info
    
    def _check_suspicious_patterns(self) -> List[str]:
        """Check for suspicious strings/patterns in file content."""
        patterns = []
        
        try:
            with self.file_path.open('rb') as f:
                sample = f.read(100000)  # Read 100KB sample
            
            text = sample.decode('latin-1', errors='ignore')
            
            # URLs
            urls = re.findall(r'https?://[^\s<>"]+', text)
            if urls:
                patterns.append(f'{len(urls)} URL(s) found')
            
            # IP addresses
            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
            if ips:
                patterns.append(f'{len(ips)} IP address(es) found')
            
            # Suspicious keywords
            suspicious = ['eval', 'exec', 'system', 'shell', 'cmd', 'powershell']
            found = [kw for kw in suspicious if kw.lower() in text.lower()]
            if found:
                patterns.append(f'Suspicious keywords: {", ".join(found)}')
        
        except Exception:
            pass
        
        return patterns
    
    def _calculate_entropy(self) -> float:
        """Calculate Shannon entropy (0-8 scale)."""
        import math
        from collections import Counter
        
        try:
            with self.file_path.open('rb') as f:
                data = f.read(100000)  # Sample 100KB
            
            if not data:
                return 0.0
            
            counter = Counter(data)
            length = len(data)
            
            entropy = 0.0
            for count in counter.values():
                p = count / length
                entropy -= p * math.log2(p)
            
            return round(entropy, 2)
        
        except Exception:
            return 0.0
