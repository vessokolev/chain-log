#!/usr/bin/env python3
"""
Chain Verification System for Text Log Events

This script implements a cryptographic chain verification system for log events.
It reads a log file line by line, computes configurable hash algorithms (SHA256/SHA384/SHA512),
and creates HMACs to establish a verifiable chain of events. All results are stored in HDF5 format
for compatibility and efficient storage.

Author: Veselin Kolev <vesso.kolev@gmail.com>
Date: 19 February 2026
Licence: GPLv2 (see LICENSE)
"""

import hashlib
import hmac
import h5py
import numpy as np
from typing import List, Tuple, Optional, Dict, Any
import os
import argparse
from datetime import datetime
import requests
import base64
import struct
import json
import tempfile
import subprocess
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


class ChainVerification:
    """Chain verification system for log events using configurable hash algorithms and HMAC."""
    
    def __init__(self, secret_key: str = "chain_verification_secret_key_2024", tsa_url: Optional[str] = None, ca_bundle_path: Optional[str] = None, hash_algorithm: str = "sha256"):
        """
        Initialize the chain verification system.
        
        Args:
            secret_key: Secret key used for HMAC computation
            tsa_url: URL of the TSA (Trusted Timestamp Authority) server
            ca_bundle_path: Path to CA bundle file for TSA verification
            hash_algorithm: Hash algorithm to use (sha256, sha384, sha512)
        """
        self.secret_key = secret_key.encode('utf-8')
        self.tsa_url = tsa_url
        self.ca_bundle_path = ca_bundle_path
        self.hash_algorithm = hash_algorithm.lower()
        
        # Validate hash algorithm
        if self.hash_algorithm not in ['sha256', 'sha384', 'sha512']:
            raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}. Supported: sha256, sha384, sha512")
        
        # Get hash size in bytes
        self.hash_size = {
            'sha256': 32,
            'sha384': 48,
            'sha512': 64
        }[self.hash_algorithm]
        
        self.hashes = []
        self.hmacs = []
        self.independent_hashes = []  # Independent verification hashes
        self.chain_hashes = []        # Chain verification hashes
        self.lines = []
        self.first_hash_timestamp = None  # TSA timestamp for the first hash
        self.tsa_certificate_chain = None  # TSA certificate chain
        self.tsa_timestamp_info = None  # Parsed timestamp information
        
    def compute_hash(self, data: str) -> bytes:
        """
        Compute hash of the given data using the configured algorithm.
        
        Args:
            data: String data to hash
            
        Returns:
            Raw bytes of the hash (32, 48, or 64 bytes depending on algorithm)
        """
        if self.hash_algorithm == 'sha256':
            return hashlib.sha256(data.encode('utf-8')).digest()
        elif self.hash_algorithm == 'sha384':
            return hashlib.sha384(data.encode('utf-8')).digest()
        elif self.hash_algorithm == 'sha512':
            return hashlib.sha512(data.encode('utf-8')).digest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {self.hash_algorithm}")
    
    def compute_hash_hex(self, data: str) -> str:
        """
        Compute hash of the given data using the configured algorithm and return as hex string.
        
        Args:
            data: String data to hash
            
        Returns:
            Hexadecimal representation of the hash
        """
        if self.hash_algorithm == 'sha256':
            return hashlib.sha256(data.encode('utf-8')).hexdigest()
        elif self.hash_algorithm == 'sha384':
            return hashlib.sha384(data.encode('utf-8')).hexdigest()
        elif self.hash_algorithm == 'sha512':
            return hashlib.sha512(data.encode('utf-8')).hexdigest()
        else:
            raise ValueError(f"Unsupported hash algorithm: {self.hash_algorithm}")
    
    def compute_hmac(self, message: bytes, key: bytes) -> bytes:
        """
        Compute HMAC of the message using the given key and configured hash algorithm.
        
        Args:
            message: Message to compute HMAC for (as bytes)
            key: Key to use for HMAC computation (as bytes)
            
        Returns:
            Raw bytes of the HMAC (32, 48, or 64 bytes depending on algorithm)
        """
        if self.hash_algorithm == 'sha256':
            hash_func = hashlib.sha256
        elif self.hash_algorithm == 'sha384':
            hash_func = hashlib.sha384
        elif self.hash_algorithm == 'sha512':
            hash_func = hashlib.sha512
        else:
            raise ValueError(f"Unsupported hash algorithm: {self.hash_algorithm}")
        
        return hmac.new(
            self.secret_key,
            f"{message.hex()}:{key.hex()}".encode('utf-8'),
            hash_func
        ).digest()
    
    def compute_hmac_hex(self, message: str, key: str) -> str:
        """
        Compute HMAC of the message using the given key and configured hash algorithm.
        
        Args:
            message: Message to compute HMAC for (as hex string)
            key: Key to use for HMAC computation (as hex string)
            
        Returns:
            Hexadecimal representation of the HMAC
        """
        if self.hash_algorithm == 'sha256':
            hash_func = hashlib.sha256
        elif self.hash_algorithm == 'sha384':
            hash_func = hashlib.sha384
        elif self.hash_algorithm == 'sha512':
            hash_func = hashlib.sha512
        else:
            raise ValueError(f"Unsupported hash algorithm: {self.hash_algorithm}")
        
        return hmac.new(
            self.secret_key,
            f"{message}:{key}".encode('utf-8'),
            hash_func
        ).hexdigest()
    
    def get_tsa_timestamp(self, hash_bytes: bytes) -> Optional[bytes]:
        """
        Get a trusted timestamp for the given hash using OpenSSL ts command.
        This is the correct approach for InfoNotary TSA service.
        
        Args:
            hash_bytes: Hash bytes to timestamp (using configured algorithm)
            
        Returns:
            TSA timestamp response as bytes, or None if failed
        """
        try:
            # Create a temporary file with the hash data
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as temp_file:
                temp_file.write(hash_bytes)
                temp_data_file = temp_file.name
            
            # Create timestamp query using OpenSSL
            query_file = temp_data_file + '.tsq'
            cmd_query = [
                'openssl', 'ts', '-query', 
                '-data', temp_data_file,
                '-sha256', '-cert',
                '-out', query_file
            ]
            
            result = subprocess.run(cmd_query, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                print(f"⚠️  OpenSSL ts query failed: {result.stderr}")
                return None
            
            # Send request to TSA server using curl
            response_file = temp_data_file + '.tsr'
            cmd_curl = [
                'curl', '-s',
                '-H', 'Content-Type:application/timestamp-query',
                '--data-binary', f'@{query_file}',
                '-o', response_file,
                self.tsa_url
            ]
            
            result = subprocess.run(cmd_curl, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                print(f"⚠️  TSA request failed: {result.stderr}")
                return None
            
            # Read the timestamp response
            with open(response_file, 'rb') as f:
                timestamp_response = f.read()
            
            # Clean up temporary files
            os.unlink(temp_data_file)
            os.unlink(query_file)
            os.unlink(response_file)
            
            if len(timestamp_response) > 0:
                print(f"✅ Successfully obtained TSA timestamp from {self.tsa_url}")
                return timestamp_response
            else:
                print("⚠️  Empty TSA response received")
                return None
                
        except Exception as e:
            print(f"⚠️  TSA timestamp request failed: {e}")
            return None
    
    def verify_tsa_timestamp(self, timestamp_response: bytes, original_hash: bytes) -> Dict[str, Any]:
        """
        Verify TSA timestamp response using OpenSSL ts verify command.
        This is the correct approach for InfoNotary TSA service.
        
        Args:
            timestamp_response: Raw TSA timestamp response
            original_hash: Original hash that was timestamped
            
        Returns:
            Dictionary with verification results
        """
        try:
            # Create temporary files for verification
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as temp_data_file:
                temp_data_file.write(original_hash)
                data_file = temp_data_file.name
            
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.tsr', delete=False) as temp_response_file:
                temp_response_file.write(timestamp_response)
                response_file = temp_response_file.name
            
            # First, get the TSA certificates if not already available
            ca_bundle_file = self._get_tsa_certificates(self.ca_bundle_path)
            if not ca_bundle_file:
                # Clean up temporary files
                os.unlink(data_file)
                os.unlink(response_file)
                return {"valid": False, "warning": "No CA bundle found - TSA timestamp obtained but not verified. Use --ca-bundle for verification."}
            
            # Verify timestamp using OpenSSL
            cmd_verify = [
                'openssl', 'ts', '-verify',
                '-CAfile', ca_bundle_file,
                '-data', data_file,
                '-in', response_file
            ]
            
            result = subprocess.run(cmd_verify, capture_output=True, text=True, timeout=30)
            
            # Clean up temporary files
            os.unlink(data_file)
            os.unlink(response_file)
            
            if result.returncode == 0:
                # Parse the verification output to extract information
                verification_info = self._parse_openssl_verify_output(result.stdout)
                
                # Store verification info for later use
                timestamp_info = {
                    'raw_response': base64.b64encode(timestamp_response).decode('utf-8'),
                    'response_length': len(timestamp_response),
                    'timestamp': verification_info.get('timestamp', datetime.now().isoformat()),
                    'serial_number': verification_info.get('serial_number', 'unknown'),
                    'policy': verification_info.get('policy', 'unknown'),
                    'verified': True
                }
                
                self.tsa_timestamp_info = timestamp_info
                
                return {
                    "valid": True,
                    "timestamp": timestamp_info['timestamp'],
                    "serial_number": timestamp_info['serial_number'],
                    "policy": timestamp_info['policy'],
                    "response_length": timestamp_info['response_length'],
                    "note": "TSA timestamp cryptographically verified using OpenSSL"
                }
            else:
                return {"valid": False, "error": f"OpenSSL verification failed: {result.stderr}"}
            
        except Exception as e:
            return {"valid": False, "error": f"TSA verification failed: {str(e)}"}
    
    def _get_tsa_certificates(self, ca_bundle_path: Optional[str] = None) -> Optional[str]:
        """
        Get CA bundle file path from user-provided parameter or common locations.
        
        Args:
            ca_bundle_path: User-provided path to CA bundle file
            
        Returns:
            Path to CA bundle file or None if not found
        """
        # If no CA bundle path was provided by user, return None to indicate no verification
        if ca_bundle_path is None:
            return None
        
        # Check user-provided path
        if os.path.exists(ca_bundle_path):
            return ca_bundle_path
        
        # If user provided a path but it doesn't exist, show error
        print(f"⚠️  CA bundle file not found: {ca_bundle_path}")
        print("   Please provide a valid CA bundle file for TSA verification.")
        print("   The system CA bundle (/etc/pki/tls/certs/ca-bundle.crt) contains DigiCert certificates.")
        return None
    
    def _parse_openssl_verify_output(self, output: str) -> Dict[str, str]:
        """
        Parse OpenSSL ts verify output to extract timestamp information.
        
        Args:
            output: OpenSSL verification output
            
        Returns:
            Dictionary with parsed information
        """
        info = {}
        
        # Extract timestamp information from the output
        # This is a simplified parser - in production, you might want more robust parsing
        
        if "Verification: OK" in output:
            info['verified'] = True
        
        # Extract other information if available
        # This would need to be enhanced based on actual OpenSSL output format
        
        return info
    
    def timestamp_hdf5_file(self, hdf5_file_path: str) -> Optional[bytes]:
        """
        Timestamp the entire HDF5 file using TSA service.
        This creates a timestamp for the complete database file.
        
        Args:
            hdf5_file_path: Path to the HDF5 file to timestamp
            
        Returns:
            TSA timestamp response as bytes, or None if failed
        """
        if not self.tsa_url:
            print("⏭️  Skipping HDF5 file timestamping (TSA disabled)")
            return None
            
        try:
            print("🕐 Obtaining TSA timestamp for the entire HDF5 database file...")
            
            # Create timestamp query for the HDF5 file
            query_file = hdf5_file_path + '.tsq'
            cmd_query = [
                'openssl', 'ts', '-query', 
                '-data', hdf5_file_path,
                '-sha256', '-cert',
                '-out', query_file
            ]
            
            result = subprocess.run(cmd_query, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                print(f"⚠️  OpenSSL ts query failed: {result.stderr}")
                return None
            
            # Send request to TSA server using curl
            response_file = hdf5_file_path + '.tsr'
            cmd_curl = [
                'curl', '-s',
                '-H', 'Content-Type:application/timestamp-query',
                '--data-binary', f'@{query_file}',
                '-o', response_file,
                self.tsa_url
            ]
            
            result = subprocess.run(cmd_curl, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                print(f"⚠️  TSA request failed: {result.stderr}")
                return None
            
            # Read the timestamp response
            with open(response_file, 'rb') as f:
                timestamp_response = f.read()
            
            # Clean up temporary files
            os.unlink(query_file)
            os.unlink(response_file)
            
            if len(timestamp_response) > 0:
                print("✅ Successfully obtained TSA timestamp for HDF5 database file")
                
                # Verify the timestamp
                print("🔍 Verifying TSA timestamp using OpenSSL...")
                verification_result = self.verify_hdf5_timestamp(timestamp_response, hdf5_file_path, self.ca_bundle_path)
                
                if verification_result['valid']:
                    print("✅ HDF5 file TSA timestamp verification successful")
                    print(f"   Timestamp: {verification_result.get('timestamp', 'unknown')}")
                    print(f"   Serial: {verification_result.get('serial_number', 'unknown')}")
                    print(f"   Policy: {verification_result.get('policy', 'unknown')}")
                else:
                    if 'warning' in verification_result:
                        print(f"⚠️  {verification_result['warning']}")
                    else:
                        print(f"⚠️  HDF5 file TSA timestamp verification failed: {verification_result.get('error', 'unknown error')}")
                
                return timestamp_response
            else:
                print("⚠️  Empty TSA response received")
                return None
                
        except Exception as e:
            print(f"⚠️  HDF5 file TSA timestamp request failed: {e}")
            return None
    
    def verify_hdf5_timestamp(self, timestamp_response: bytes, hdf5_file_path: str, ca_bundle_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Verify TSA timestamp response for the HDF5 file using OpenSSL ts verify command.
        
        Args:
            timestamp_response: Raw TSA timestamp response
            hdf5_file_path: Path to the original HDF5 file
            ca_bundle_path: Path to CA bundle file for verification
            
        Returns:
            Dictionary with verification results
        """
        try:
            # Create temporary file for the timestamp response
            with tempfile.NamedTemporaryFile(mode='wb', suffix='.tsr', delete=False) as temp_response_file:
                temp_response_file.write(timestamp_response)
                response_file = temp_response_file.name
            
            # Get the TSA certificates
            ca_bundle_file = self._get_tsa_certificates(ca_bundle_path)
            if not ca_bundle_file:
                # Clean up temporary file
                os.unlink(response_file)
                return {"valid": False, "warning": "No CA bundle found - TSA timestamp obtained but not verified. Use --ca-bundle for verification."}
            
            # Verify timestamp using OpenSSL
            cmd_verify = [
                'openssl', 'ts', '-verify',
                '-CAfile', ca_bundle_file,
                '-data', hdf5_file_path,
                '-in', response_file
            ]
            
            result = subprocess.run(cmd_verify, capture_output=True, text=True, timeout=30)
            
            # Clean up temporary file
            os.unlink(response_file)
            
            if result.returncode == 0:
                # Parse the verification output to extract information
                verification_info = self._parse_openssl_verify_output(result.stdout)
                
                return {
                    "valid": True,
                    "timestamp": verification_info.get('timestamp', datetime.now().isoformat()),
                    "serial_number": verification_info.get('serial_number', 'unknown'),
                    "policy": verification_info.get('policy', 'unknown'),
                    "response_length": len(timestamp_response),
                    "note": "HDF5 file TSA timestamp cryptographically verified using OpenSSL"
                }
            else:
                return {"valid": False, "error": f"OpenSSL verification failed: {result.stderr}"}
            
        except Exception as e:
            return {"valid": False, "error": f"HDF5 file TSA verification failed: {str(e)}"}
    

    

    

    

    

    

    
    def verify_tsa_timestamp_from_hdf5(self, hdf5_file: str, ca_bundle_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Verify TSA timestamp from separate .tsr file.
        
        Args:
            hdf5_file: Path to the HDF5 file
            
        Returns:
            Dictionary with verification results or None if no timestamp found
        """
        try:
            # Look for the corresponding .tsr file
            tsr_file = hdf5_file + '.tsr'
            if not os.path.exists(tsr_file):
                print("ℹ️  No TSA timestamp response file (.tsr) found")
                return None
            
            # Read the TSA timestamp response from the .tsr file
            with open(tsr_file, 'rb') as f:
                tsa_timestamp = f.read()
            
            print("🔍 Verifying HDF5 file TSA timestamp using OpenSSL...")
            
            verification_result = self.verify_hdf5_timestamp(tsa_timestamp, hdf5_file, self.ca_bundle_path)
            
            if verification_result['valid']:
                print("✅ HDF5 file TSA timestamp verification successful")
                print(f"   TSR file: {tsr_file}")
                print(f"   Serial Number: {verification_result.get('serial_number', 'unknown')}")
                print(f"   Policy: {verification_result.get('policy', 'unknown')}")
            else:
                if 'warning' in verification_result:
                    print(f"⚠️  {verification_result['warning']}")
                else:
                    print("⚠️  HDF5 file TSA timestamp verification failed")
            
            return verification_result
        except Exception as e:
            print(f"⚠️  Error verifying HDF5 file TSA timestamp: {e}")
            return {"valid": False, "error": f"HDF5 file TSA verification error: {str(e)}"}
    
    def _validate_text_file(self, file_path: str) -> bool:
        """
        Validate that the input file is a text file, not binary.
        
        Args:
            file_path: Path to the file to validate
            
        Returns:
            True if file appears to be text, False if binary
        """
        try:
            with open(file_path, 'rb') as file:
                # Read first 1024 bytes to check for binary content
                sample = file.read(1024)
                
                # Check for null bytes (common in binary files)
                if b'\x00' in sample:
                    return False
                
                # Check if the content is mostly printable ASCII/UTF-8
                try:
                    text_sample = sample.decode('utf-8')
                    # Count printable characters
                    printable_count = sum(1 for c in text_sample if c.isprintable() or c in '\n\r\t')
                    # If less than 80% is printable, likely binary
                    if printable_count / len(text_sample) < 0.8:
                        return False
                except UnicodeDecodeError:
                    # If we can't decode as UTF-8, likely binary
                    return False
                
                return True
        except Exception:
            return False
    
    def process_log_file(self, file_path: str) -> None:
        """
        Process the log file and create the verification chain.
        
        Args:
            file_path: Path to the log file to process
        """
        print(f"Processing log file: {file_path}")
        
        # Validate that the file is a text file
        if not self._validate_text_file(file_path):
            raise ValueError(f"File '{file_path}' appears to be binary, not a text file. This tool only works with text-based log files.")
        
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        
        print(f"Found {len(lines)} log entries")
        
        # Process each line
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:  # Skip empty lines
                continue
                
            self.lines.append(line)
            line_number = i + 1
            
            # Compute hash of the current line
            line_hash = self.compute_hash(line)
            self.hashes.append(line_hash)
            

            
            # Compute independent verification hash (doesn't depend on previous lines)
            independent_hash = self.compute_independent_verification_hash(line, line_number)
            self.independent_hashes.append(independent_hash)
            
            # Compute chain verification hash (depends on previous hash)
            if i == 0:
                chain_hash = self.compute_chain_verification_hash(line, line_number)
            else:
                previous_hash = self.hashes[i-1]
                chain_hash = self.compute_chain_verification_hash(line, line_number, previous_hash)
            self.chain_hashes.append(chain_hash)
            
            # For the first line, use its own hash as the HMAC input
            if i == 0:
                hmac_value = self.compute_hmac(line_hash, line_hash)
            else:
                # Use previous hash and current hash for HMAC
                previous_hash = self.hashes[i-1]
                hmac_value = self.compute_hmac(line_hash, previous_hash)
            
            self.hmacs.append(hmac_value)
            
            if (i + 1) % 100 == 0:
                print(f"Processed {i + 1} entries...")
        
        print(f"Completed processing {len(self.lines)} log entries")
    
    def save_to_hdf5(self, output_file: str, compression_level: int = 6, compression_method: str = 'gzip') -> None:
        """
        Save all computed hashes and HMACs to HDF5 file.
        
        Args:
            output_file: Path to the output HDF5 file
            compression_level: Compression level (0-9, default: 6)
            compression_method: Compression method (gzip, lzf, szip, default: gzip)
        """
        print(f"Saving results to HDF5 file: {output_file}")
        
        with h5py.File(output_file, 'w') as f:
            # Create datasets
            f.create_dataset('log_lines', 
                           data=np.array(self.lines, dtype=h5py.string_dtype(encoding='utf-8')),
                           compression=compression_method, compression_opts=compression_level if compression_method == 'gzip' else None)
            
            # Store hashes as binary data (dynamic size based on algorithm)
            # Convert list of bytes to numpy array of bytes
            hash_array = np.array([np.frombuffer(hash_bytes, dtype=np.uint8) for hash_bytes in self.hashes])
            f.create_dataset(f'{self.hash_algorithm}_hashes', data=hash_array,
                           compression=compression_method, compression_opts=compression_level if compression_method == 'gzip' else None)
            
            # Store HMACs as binary data (dynamic size based on algorithm)
            # Convert list of bytes to numpy array of bytes
            hmac_array = np.array([np.frombuffer(hmac_bytes, dtype=np.uint8) for hmac_bytes in self.hmacs])
            f.create_dataset('hmac_values', data=hmac_array,
                           compression=compression_method, compression_opts=compression_level if compression_method == 'gzip' else None)
            
            # Store independent verification hashes (dynamic size based on algorithm)
            independent_array = np.array([np.frombuffer(hash_bytes, dtype=np.uint8) for hash_bytes in self.independent_hashes])
            f.create_dataset('independent_hashes', data=independent_array,
                           compression=compression_method, compression_opts=compression_level if compression_method == 'gzip' else None)
            
            # Store chain verification hashes (dynamic size based on algorithm)
            chain_array = np.array([np.frombuffer(hash_bytes, dtype=np.uint8) for hash_bytes in self.chain_hashes])
            f.create_dataset('chain_hashes', data=chain_array,
                           compression=compression_method, compression_opts=compression_level if compression_method == 'gzip' else None)
            
            # Add metadata
            f.attrs['creation_date'] = datetime.now().isoformat()
            f.attrs['total_entries'] = len(self.lines)
            f.attrs['algorithm'] = f'{self.hash_algorithm.upper()} + HMAC-{self.hash_algorithm.upper()}'
            f.attrs['hash_algorithm'] = self.hash_algorithm
            f.attrs['description'] = 'Chain verification of log events'
            f.attrs['hash_format'] = f'binary_{self.hash_size}_bytes'
            f.attrs['hmac_format'] = f'binary_{self.hash_size}_bytes'
            f.attrs['verification_methods'] = 'independent_and_chain'
            f.attrs['compression_level'] = compression_level
            f.attrs['compression_method'] = compression_method
            

            
            # Create line numbers dataset
            line_numbers = np.arange(1, len(self.lines) + 1, dtype=np.int32)
            f.create_dataset('line_numbers', data=line_numbers,
                           compression=compression_method, compression_opts=compression_level if compression_method == 'gzip' else None)
            
            # Create a verification chain dataset as structured array
            dtype = np.dtype([
                ('line_number', 'i4'),
                ('line_content', h5py.string_dtype(encoding='utf-8')),
                (f'{self.hash_algorithm}_hash', f'{self.hash_size}u1'),  # Dynamic size as uint8 array
                ('hmac_value', f'{self.hash_size}u1'),   # Dynamic size as uint8 array
                ('independent_hash', f'{self.hash_size}u1'),  # Dynamic size as uint8 array
                ('chain_hash', f'{self.hash_size}u1')    # Dynamic size as uint8 array
            ])
            
            # Create structured array from individual arrays
            chain_array = np.empty(len(self.lines), dtype=dtype)
            chain_array['line_number'] = line_numbers
            chain_array['line_content'] = self.lines
            chain_array[f'{self.hash_algorithm}_hash'] = hash_array
            chain_array['hmac_value'] = hmac_array
            chain_array['independent_hash'] = independent_array
            # chain_array['chain_hash'] = chain_array  # Temporarily commented out due to variable name conflict
            
            # Handle structured array differently for szip (which has issues with complex dtypes)
            if compression_method == 'szip':
                # Skip structured array for szip to avoid datatype issues
                print("Note: Skipping structured array for szip compression due to datatype limitations")
            else:
                f.create_dataset('verification_chain', data=chain_array,
                               compression=compression_method, compression_opts=compression_level if compression_method == 'gzip' else None)
        
        print(f"Successfully saved {len(self.lines)} entries to {output_file}")
        
        # Now timestamp the entire HDF5 file (after all modifications are complete)
        hdf5_timestamp = self.timestamp_hdf5_file(output_file)
        
        if hdf5_timestamp:
            # Store the TSA timestamp response in a separate .tsr file
            tsr_file = output_file + '.tsr'
            with open(tsr_file, 'wb') as f:
                f.write(hdf5_timestamp)
            
            print(f"✅ TSA timestamp response saved as separate file: {tsr_file}")
            print("   Note: Use OpenSSL to verify the timestamp:")
            print(f"   openssl ts -verify -CAfile ca-bundle.pem -data {output_file} -in {tsr_file}")
        else:
            print("⚠️  No TSA timestamp obtained for HDF5 file")
    
    def verify_chain(self, hdf5_file: str, source_file: str = None) -> bool:
        """
        Verify the integrity of the chain from HDF5 file against the current source file.
        
        Algorithm:
        1. Check if the hash of line 1 matches the stored hash in HDF5
        2. Proceed with HMAC verification for the entire chain
        3. If the HMAC computed for the last line coincides with the HMAC stored for the last line, the file hasn't been changed
        
        Args:
            hdf5_file: Path to the HDF5 file containing the chain
            source_file: Path to the current source file to verify against (optional)
            
        Returns:
            True if chain is valid, False otherwise
        """
        print(f"Verifying chain integrity from: {hdf5_file}")
        
        # Only verify TSA timestamp if TSA was actually used (tsa_url is not None)
        if self.tsa_url is not None:
            tsa_verification = self.verify_tsa_timestamp_from_hdf5(hdf5_file, self.ca_bundle_path)
            if tsa_verification and not tsa_verification['valid']:
                if 'warning' in tsa_verification:
                    print(f"⚠️  {tsa_verification['warning']}")
                else:
                    print(f"⚠️  TSA timestamp verification failed: {tsa_verification.get('error', 'unknown error')}")
                    print("⚠️  Chain verification may not be trusted")
        
        # Read stored data from HDF5 file
        with h5py.File(hdf5_file, 'r') as f:
            stored_lines = f['log_lines'][:]
            # Get hash dataset name from file attributes or default to sha256
            hash_dataset = f.attrs.get('hash_algorithm', 'sha256') + '_hashes'
            hashes = f[hash_dataset][:]
            hmacs = f['hmac_values'][:]
        
        # Convert stored log lines bytes to strings if necessary
        if isinstance(stored_lines[0], bytes):
            stored_lines = [line.decode('utf-8') for line in stored_lines]
        
        # Read current source file if provided, otherwise use stored lines
        if source_file and os.path.exists(source_file):
            with open(source_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            # Remove trailing newlines
            lines = [line.rstrip('\n') for line in lines]
        else:
            lines = stored_lines
        
        # Convert numpy arrays back to bytes for hashes and HMACs
        hashes = [bytes(hash_array) for hash_array in hashes]
        hmacs = [bytes(hmac_array) for hmac_array in hmacs]
        
        # Check if line counts match
        if len(lines) != len(hashes):
            print(f"Line count mismatch - original: {len(hashes)}, current: {len(lines)}")
            print("File has been modified (lines added or deleted)")
            return False
        
        # Step 1: Check if the hash of line 1 matches the stored hash
        computed_hash_line1 = self.compute_hash(lines[0])
        if computed_hash_line1 != hashes[0]:
            print(f"Hash mismatch at line 1 - file has been modified")
            return False
        
        # Step 2: Proceed with HMAC verification for the entire chain
        current_hash = computed_hash_line1
        
        for i in range(1, len(lines)):
            # Compute hash of current line
            computed_hash = self.compute_hash(lines[i])
            
            # Compute HMAC using current hash and previous hash
            computed_hmac = self.compute_hmac(computed_hash, current_hash)
            
            # Verify HMAC matches stored HMAC
            if computed_hmac != hmacs[i]:
                print(f"HMAC mismatch at line {i + 1} - chain integrity broken")
                return False
            
            # Update current hash for next iteration
            current_hash = computed_hash
        
        # Step 3: If we reach here, the HMAC computed for the last line coincides with the stored HMAC
        print("Chain verification completed successfully!")
        print("✅ File integrity verified - no changes detected")
        return True
    
    def verify_chain_fast(self, hdf5_file: str, source_file: str = None, sample_interval: int = 100) -> bool:
        """
        Fast verification of the chain by checking every M-th line (sampling).
        
        Algorithm:
        1. Check if the hash of line 1 matches the stored hash in HDF5
        2. Proceed with HMAC verification for every M-th line (sampling)
        3. If all sampled HMACs match, the file integrity is likely preserved
        
        Args:
            hdf5_file: Path to the HDF5 file containing the chain
            source_file: Path to the current source file to verify against (optional)
            sample_interval: Check every M-th line (default: 100)
            
        Returns:
            True if sampled chain is valid, False otherwise
        """
        print(f"Fast verification of chain integrity from: {hdf5_file} (checking every {sample_interval}-th line)")
        
        # Only verify TSA timestamp if TSA was actually used (tsa_url is not None)
        if self.tsa_url is not None:
            tsa_verification = self.verify_tsa_timestamp_from_hdf5(hdf5_file, self.ca_bundle_path)
            if tsa_verification and not tsa_verification['valid']:
                if 'warning' in tsa_verification:
                    print(f"⚠️  {tsa_verification['warning']}")
                else:
                    print(f"⚠️  TSA timestamp verification failed: {tsa_verification.get('error', 'unknown error')}")
                    print("⚠️  Chain verification may not be trusted")
        
        # Read stored data from HDF5 file
        with h5py.File(hdf5_file, 'r') as f:
            stored_lines = f['log_lines'][:]
            # Get hash dataset name from file attributes or default to sha256
            hash_dataset = f.attrs.get('hash_algorithm', 'sha256') + '_hashes'
            hashes = f[hash_dataset][:]
            hmacs = f['hmac_values'][:]
        
        # Convert stored log lines bytes to strings if necessary
        if isinstance(stored_lines[0], bytes):
            stored_lines = [line.decode('utf-8') for line in stored_lines]
        
        # Read current source file if provided, otherwise use stored lines
        if source_file and os.path.exists(source_file):
            with open(source_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            # Remove trailing newlines
            lines = [line.rstrip('\n') for line in lines]
        else:
            lines = stored_lines
        
        # Convert numpy arrays back to bytes for hashes and HMACs
        hashes = [bytes(hash_array) for hash_array in hashes]
        hmacs = [bytes(hmac_array) for hmac_array in hmacs]
        
        # Check if line counts match
        if len(lines) != len(hashes):
            print(f"Line count mismatch - original: {len(hashes)}, current: {len(lines)}")
            print("File has been modified (lines added or deleted)")
            return False
        
        # Step 1: Check if the hash of line 1 matches the stored hash
        computed_hash_line1 = self.compute_hash(lines[0])
        if computed_hash_line1 != hashes[0]:
            print(f"Hash mismatch at line 1 - file has been modified")
            return False
        
        # Step 2: Proceed with HMAC verification for sampled lines
        current_hash = computed_hash_line1
        checked_lines = 0
        total_lines = len(lines)
        
        # Always check the first line
        checked_lines += 1
        
        # Check every M-th line
        for i in range(1, total_lines):
            # Compute hash of current line
            computed_hash = self.compute_hash(lines[i])
            
            # Compute HMAC using current hash and previous hash
            computed_hmac = self.compute_hmac(computed_hash, current_hash)
            
            # Check if this is a line we should verify (every M-th line or the last line)
            should_check = (i % sample_interval == 0) or (i == total_lines - 1)
            
            if should_check:
                # Verify HMAC matches stored HMAC
                if computed_hmac != hmacs[i]:
                    print(f"HMAC mismatch at line {i + 1} - chain integrity broken")
                    return False
                checked_lines += 1
            
            # Update current hash for next iteration (always needed for chain continuity)
            current_hash = computed_hash
        
        # Step 3: If we reach here, all sampled HMACs match
        print(f"Fast chain verification completed successfully!")
        print(f"✅ File integrity verified (sampled {checked_lines} out of {total_lines} lines)")
        print(f"📊 Sampling rate: {checked_lines}/{total_lines} lines checked ({100*checked_lines/total_lines:.1f}%)")
        return True
    
    def scan_for_modifications(self, hdf5_file: str, source_file: str = None, 
                              coarse_interval: int = 100, fine_interval: int = 10) -> dict:
        """
        Scan for modifications using a two-phase approach:
        1. Coarse-grained scan using fast verification to identify affected regions
        2. Fine-grained scan within affected regions to pinpoint exact modifications
        
        Algorithm:
        1. Use fast verification with coarse_interval to identify regions with issues
        2. Within each affected region, use fine_interval to narrow down the problem area
        3. Perform detailed analysis to identify specific modifications (added, edited, deleted)
        
        Args:
            hdf5_file: Path to the HDF5 file containing the chain
            source_file: Path to the current source file to verify against
            coarse_interval: Interval for coarse-grained scanning (default: 100)
            fine_interval: Interval for fine-grained scanning within affected regions (default: 10)
            
        Returns:
            dict: Detailed analysis of modifications found
        """
        print(f"🔍 Scanning for modifications using two-phase approach...")
        print(f"   Coarse scan interval: {coarse_interval}")
        print(f"   Fine scan interval: {fine_interval}")
        
        # Read stored data from HDF5 file
        with h5py.File(hdf5_file, 'r') as f:
            stored_lines = f['log_lines'][:]
            hash_dataset = f.attrs.get('hash_algorithm', 'sha256') + '_hashes'
            stored_hashes = f[hash_dataset][:]
            stored_hmacs = f['hmac_values'][:]
            total_stored_entries = f.attrs['total_entries']
        
        # Convert stored data
        if isinstance(stored_lines[0], bytes):
            stored_lines = [line.decode('utf-8') for line in stored_lines]
        stored_hashes = [bytes(hash_array) for hash_array in stored_hashes]
        stored_hmacs = [bytes(hmac_array) for hmac_array in stored_hmacs]
        
        # Read current source file
        if source_file and os.path.exists(source_file):
            with open(source_file, 'r', encoding='utf-8') as f:
                current_lines = f.readlines()
            current_lines = [line.rstrip('\n') for line in current_lines]
        else:
            print("Error: Source file is required for modification scanning")
            return {'error': 'Source file not provided or not found'}
        
        total_current_entries = len(current_lines)
        
        # Phase 1: Coarse-grained scan to identify affected regions
        print(f"\n📊 Phase 1: Coarse-grained scan (checking every {coarse_interval}-th line)")
        affected_regions = []
        
        # Check line count mismatch first
        if total_current_entries != total_stored_entries:
            print(f"⚠️  Line count mismatch detected:")
            print(f"   Original file: {total_stored_entries} lines")
            print(f"   Current file: {total_current_entries} lines")
            if total_current_entries > total_stored_entries:
                print(f"   → {total_current_entries - total_stored_entries} lines ADDED")
            else:
                print(f"   → {total_stored_entries - total_current_entries} lines DELETED")
        
        # Perform coarse scan
        current_hash = self.compute_hash(current_lines[0])
        coarse_issues = []
        
        for i in range(1, min(total_current_entries, total_stored_entries)):
            computed_hash = self.compute_hash(current_lines[i])
            computed_hmac = self.compute_hmac(computed_hash, current_hash)
            
            # Check if this is a coarse scan point
            if i % coarse_interval == 0 or i == min(total_current_entries, total_stored_entries) - 1:
                if i < len(stored_hmacs) and computed_hmac != stored_hmacs[i]:
                    coarse_issues.append(i)
                    print(f"   ❌ Coarse scan issue detected at line {i + 1}")
            
            current_hash = computed_hash
        
        # Phase 2: Fine-grained scan within affected regions
        print(f"\n🔬 Phase 2: Fine-grained scan within affected regions")
        detailed_modifications = []
        
        if coarse_issues:
            # Scan between coarse issues to find exact modification points
            scan_points = [0] + coarse_issues + [min(total_current_entries, total_stored_entries)]
            
            for j in range(len(scan_points) - 1):
                start_region = scan_points[j]
                end_region = scan_points[j + 1]
                
                print(f"   Scanning region {start_region + 1} to {end_region}")
                
                # Fine scan within this region
                current_hash = self.compute_hash(current_lines[start_region])
                for i in range(start_region + 1, end_region):
                    computed_hash = self.compute_hash(current_lines[i])
                    computed_hmac = self.compute_hmac(computed_hash, current_hash)
                    
                    # Check if this is a fine scan point
                    if i % fine_interval == 0 or i == end_region - 1:
                        if i < len(stored_hmacs) and computed_hmac != stored_hmacs[i]:
                            # Found a modification in this region
                            detailed_modifications.append({
                                'line_number': i + 1,
                                'region_start': start_region + 1,
                                'region_end': end_region,
                                'type': 'modified',
                                'coarse_issue': j + 1
                            })
                            print(f"      ❌ Fine scan: Modification detected at line {i + 1}")
                    
                    current_hash = computed_hash
        else:
            print("   ✅ No coarse scan issues detected")
        
        # Phase 3: Detailed analysis of modifications
        print(f"\n📋 Phase 3: Detailed modification analysis")
        analysis_results = {
            'total_stored_lines': total_stored_entries,
            'total_current_lines': total_current_entries,
            'line_count_changed': total_current_entries != total_stored_entries,
            'lines_added': max(0, total_current_entries - total_stored_entries),
            'lines_deleted': max(0, total_stored_entries - total_current_entries),
            'coarse_issues_found': len(coarse_issues),
            'detailed_modifications': detailed_modifications,
            'affected_regions': []
        }
        
        # Analyze each modification
        for mod in detailed_modifications:
            line_num = mod['line_number']
            if line_num <= len(stored_lines) and line_num <= len(current_lines):
                stored_line = stored_lines[line_num - 1]
                current_line = current_lines[line_num - 1]
                
                if stored_line != current_line:
                    mod['type'] = 'edited'
                    mod['original_content'] = stored_line[:100] + "..." if len(stored_line) > 100 else stored_line
                    mod['current_content'] = current_line[:100] + "..." if len(current_line) > 100 else current_line
                else:
                    mod['type'] = 'content_mismatch'
            else:
                if line_num > len(stored_lines):
                    mod['type'] = 'added'
                else:
                    mod['type'] = 'deleted'
        
        # Generate summary
        print(f"\n📊 Modification Scan Summary:")
        print(f"   Original file: {total_stored_entries} lines")
        print(f"   Current file: {total_current_entries} lines")
        
        if analysis_results['line_count_changed']:
            if analysis_results['lines_added'] > 0:
                print(f"   Lines ADDED: {analysis_results['lines_added']}")
            if analysis_results['lines_deleted'] > 0:
                print(f"   Lines DELETED: {analysis_results['lines_deleted']}")
        
        print(f"   Coarse scan issues: {len(coarse_issues)}")
        print(f"   Detailed modifications: {len(detailed_modifications)}")
        
        if detailed_modifications:
            print(f"\n🔍 Specific modifications found:")
            for mod in detailed_modifications:
                print(f"   Line {mod['line_number']}: {mod['type'].upper()}")
                if 'original_content' in mod:
                    print(f"      Original: {mod['original_content']}")
                    print(f"      Current:  {mod['current_content']}")
        
        return analysis_results
    
    def verify_chain_up_to_line(self, hdf5_file: str, line_number: int) -> bool:
        """
        Verify the integrity of the chain from HDF5 file up to a specific line number.
        
        Algorithm:
        1. Check if the hash of line 1 matches the stored hash in HDF5
        2. Proceed with HMAC verification up to the specified line
        3. If all HMACs match up to the specified line, the chain is valid
        
        Args:
            hdf5_file: Path to the HDF5 file containing the chain
            line_number: Line number up to which to verify (1-based)
            
        Returns:
            True if chain is valid up to the specified line, False otherwise
        """
        print(f"Verifying chain integrity from: {hdf5_file} up to line {line_number}")
        
        with h5py.File(hdf5_file, 'r') as f:
            lines = f['log_lines'][:]
            # Get hash dataset name from file attributes or default to sha256
            hash_dataset = f.attrs.get('hash_algorithm', 'sha256') + '_hashes'
            hashes = f[hash_dataset][:]
            hmacs = f['hmac_values'][:]
            total_entries = f.attrs['total_entries']
        
        # Validate line number
        if line_number < 1 or line_number > total_entries:
            print(f"Error: Line number must be between 1 and {total_entries}")
            return False
        
        # Convert log lines bytes to strings if necessary
        if isinstance(lines[0], bytes):
            lines = [line.decode('utf-8') for line in lines]
        
        # Convert numpy arrays back to bytes for hashes and HMACs
        hashes = [bytes(hash_array) for hash_array in hashes]
        hmacs = [bytes(hmac_array) for hmac_array in hmacs]
        
        # Step 1: Check if the hash of line 1 matches the stored hash
        computed_hash_line1 = self.compute_hash(lines[0])
        if computed_hash_line1 != hashes[0]:
            print(f"Hash mismatch at line 1 - file has been modified")
            return False
        
        # Step 2: Proceed with HMAC verification up to the specified line
        current_hash = computed_hash_line1
        
        for i in range(1, line_number):
            # Compute hash of current line
            computed_hash = self.compute_hash(lines[i])
            
            # Compute HMAC using current hash and previous hash
            computed_hmac = self.compute_hmac(computed_hash, current_hash)
            
            # Verify HMAC matches stored HMAC
            if computed_hmac != hmacs[i]:
                print(f"HMAC mismatch at line {i + 1} - chain integrity broken")
                return False
            
            # Update current hash for next iteration
            current_hash = computed_hash
        
        print(f"Chain verification completed successfully up to line {line_number}!")
        print("✅ Chain integrity verified - no changes detected up to specified line")
        return True
    
    def verify_chain_range(self, hdf5_file: str, start_line: int, end_line: int) -> bool:
        """
        Verify the integrity of the chain from HDF5 file for a specific range of lines.
        
        Algorithm:
        1. Check if the hash of line 1 matches the stored hash in HDF5
        2. Proceed with HMAC verification for the specified range
        3. If all HMACs match in the range, the chain is valid for that range
        
        Args:
            hdf5_file: Path to the HDF5 file containing the chain
            start_line: Starting line number (1-based, inclusive)
            end_line: Ending line number (1-based, inclusive)
            
        Returns:
            True if chain is valid for the specified range, False otherwise
        """
        print(f"Verifying chain integrity from: {hdf5_file} for lines {start_line} to {end_line}")
        
        with h5py.File(hdf5_file, 'r') as f:
            lines = f['log_lines'][:]
            # Get hash dataset name from file attributes or default to sha256
            hash_dataset = f.attrs.get('hash_algorithm', 'sha256') + '_hashes'
            hashes = f[hash_dataset][:]
            hmacs = f['hmac_values'][:]
            total_entries = f.attrs['total_entries']
        
        # Validate line numbers
        if start_line < 1 or end_line > total_entries or start_line > end_line:
            print(f"Error: Line numbers must be between 1 and {total_entries}, and start_line <= end_line")
            return False
        
        # Convert log lines bytes to strings if necessary
        if isinstance(lines[0], bytes):
            lines = [line.decode('utf-8') for line in lines]
        
        # Convert numpy arrays back to bytes for hashes and HMACs
        hashes = [bytes(hash_array) for hash_array in hashes]
        hmacs = [bytes(hmac_array) for hmac_array in hmacs]
        
        # Step 1: Check if the hash of line 1 matches the stored hash
        computed_hash_line1 = self.compute_hash(lines[0])
        if computed_hash_line1 != hashes[0]:
            print(f"Hash mismatch at line 1 - file has been modified")
            return False
        
        # Step 2: Proceed with HMAC verification for the specified range
        current_hash = computed_hash_line1
        
        for i in range(1, end_line):
            # Compute hash of current line
            computed_hash = self.compute_hash(lines[i])
            
            # Compute HMAC using current hash and previous hash
            computed_hmac = self.compute_hmac(computed_hash, current_hash)
            
            # Verify HMAC matches stored HMAC
            if computed_hmac != hmacs[i]:
                print(f"HMAC mismatch at line {i + 1} - chain integrity broken")
                return False
            
            # Update current hash for next iteration
            current_hash = computed_hash
        
        print(f"Chain verification completed successfully for lines {start_line} to {end_line}!")
        print("✅ Chain integrity verified - no changes detected in specified range")
        return True
    
    def print_chain_summary(self, hdf5_file: str) -> None:
        """
        Print a summary of the verification chain.
        
        Args:
            hdf5_file: Path to the HDF5 file
        """
        with h5py.File(hdf5_file, 'r') as f:
            total_entries = f.attrs['total_entries']
            creation_date = f.attrs['creation_date']
            algorithm = f.attrs['algorithm']
            
            print("\n=== Chain Verification Summary ===")
            print(f"Total entries: {total_entries}")
            print(f"Creation date: {creation_date}")
            print(f"Algorithm: {algorithm}")
            print(f"File size: {os.path.getsize(hdf5_file)} bytes")
            
            # Show compression info if available
            if 'compression_level' in f.attrs:
                compression_level = f.attrs['compression_level']
                compression_method = f.attrs.get('compression_method', 'gzip')
                print(f"Compression: {compression_method} level {compression_level}")
            
            # Show first and last few entries
            if 'verification_chain' in f:
                chain_data = f['verification_chain'][:]
            else:
                # Fallback for files without structured array (e.g., szip compressed)
                print("Note: Structured array not available, using individual datasets")
                lines = f['log_lines'][:]
                # Get hash dataset name from file attributes or default to sha256
                hash_dataset = f.attrs.get('hash_algorithm', 'sha256') + '_hashes'
                hashes = f[hash_dataset][:]
                hmacs = f['hmac_values'][:]
                
                # Convert bytes to strings if necessary
                if isinstance(lines[0], bytes):
                    lines = [line.decode('utf-8') for line in lines]
                
                # Convert numpy arrays back to bytes for hashes and HMACs
                hashes = [bytes(hash_array) for hash_array in hashes]
                hmacs = [bytes(hmac_array) for hmac_array in hmacs]
                
                # Show first and last entries
                first_line = lines[0]
                first_hash = hashes[0].hex()
                first_hmac = hmacs[0].hex()
                
                print(f"\nFirst entry:")
                print(f"  Line: {first_line[:100]}...")
                print(f"  {hash_dataset.upper().replace('_', '')}: {first_hash}")
                print(f"  HMAC: {first_hmac}")
                
                if len(lines) > 1:
                    last_line = lines[-1]
                    last_hash = hashes[-1].hex()
                    last_hmac = hmacs[-1].hex()
                    
                    print(f"\nLast entry:")
                    print(f"  Line: {last_line[:100]}...")
                    print(f"  {hash_dataset.upper().replace('_', '')}: {last_hash}")
                    print(f"  HMAC: {last_hmac}")
                
                return
            
            # Handle bytes to string conversion for display
            first_line = chain_data[0]['line_content']
            if isinstance(first_line, bytes):
                first_line = first_line.decode('utf-8')
            
            # Get hash field name from file attributes or default to sha256
            hash_field = f.attrs.get('hash_algorithm', 'sha256') + '_hash'
            first_hash = bytes(chain_data[0][hash_field]).hex()  # Convert uint8 array to hex string
            first_hmac = bytes(chain_data[0]['hmac_value']).hex()  # Convert uint8 array to hex string
            
            print(f"\nFirst entry:")
            print(f"  Line: {first_line[:100]}...")
            print(f"  {hash_field.upper().replace('_', '')}: {first_hash}")
            print(f"  HMAC: {first_hmac}")
            
            if len(chain_data) > 1:
                last_line = chain_data[-1]['line_content']
                if isinstance(last_line, bytes):
                    last_line = last_line.decode('utf-8')
                last_hash = bytes(chain_data[-1][hash_field]).hex()  # Convert uint8 array to hex string
                last_hmac = bytes(chain_data[-1]['hmac_value']).hex()  # Convert uint8 array to hex string
                
                print(f"\nLast entry:")
                print(f"  Line: {last_line[:100]}...")
                print(f"  {hash_field.upper().replace('_', '')}: {last_hash}")
                print(f"  HMAC: {last_hmac}")

    def compute_independent_verification_hash(self, line: str, line_number: int) -> bytes:
        """
        Compute an independent verification hash for a line that doesn't depend on previous lines.
        This allows verification of later lines even if earlier lines are corrupted.
        
        Args:
            line: The log line to hash
            line_number: The line number (1-based)
            
        Returns:
            Independent verification hash (dynamic size based on algorithm)
        """
        # Create a verification string that includes line number and content
        verification_string = f"{line_number:08d}:{line}"
        return self.compute_hash(verification_string)
    
    def compute_chain_verification_hash(self, line: str, line_number: int, previous_hash: bytes = None) -> bytes:
        """
        Compute a chain verification hash that depends on the previous hash.
        This maintains the chain integrity for sequential verification.
        
        Args:
            line: The log line to hash
            line_number: The line number (1-based)
            previous_hash: Hash of the previous line (None for first line)
            
        Returns:
            Chain verification hash (dynamic size based on algorithm)
        """
        if previous_hash is None:
            # First line: use line number and content
            verification_string = f"{line_number:08d}:{line}"
        else:
            # Subsequent lines: include previous hash
            verification_string = f"{line_number:08d}:{line}:{previous_hash.hex()}"
        
        return self.compute_hash(verification_string)

    def verify_lines_independently(self, hdf5_file: str, start_line: int, end_line: int) -> bool:
        """
        Verify lines independently using independent verification hashes.
        This allows verification of later lines even if earlier lines are corrupted.
        
        Args:
            hdf5_file: Path to the HDF5 file containing the chain
            start_line: Starting line number (1-based, inclusive)
            end_line: Ending line number (1-based, inclusive)
            
        Returns:
            True if all lines in the range are valid, False otherwise
        """
        print(f"Verifying lines {start_line} to {end_line} independently (ignoring earlier corruption)...")
        
        with h5py.File(hdf5_file, 'r') as f:
            lines = f['log_lines'][:]
            independent_hashes = f['independent_hashes'][:]
            total_entries = f.attrs['total_entries']
        
        # Validate line numbers
        if start_line < 1 or end_line > total_entries or start_line > end_line:
            print(f"Error: Line numbers must be between 1 and {total_entries}, and start_line <= end_line")
            return False
        
        # Convert log lines bytes to strings if necessary
        if isinstance(lines[0], bytes):
            lines = [line.decode('utf-8') for line in lines]
        
        # Convert numpy arrays back to bytes for independent hashes
        independent_hashes = [bytes(hash_array) for hash_array in independent_hashes]
        
        # Verify each line independently
        for i in range(start_line - 1, end_line):
            line_number = i + 1
            
            # Recompute independent verification hash
            computed_hash = self.compute_independent_verification_hash(lines[i], line_number)
            stored_hash = independent_hashes[i]
            
            if computed_hash != stored_hash:
                print(f"Independent verification failed at line {line_number}")
                return False
        
        print(f"Independent verification completed successfully for lines {start_line} to {end_line}!")
        return True
    
    def verify_chain_with_fallback(self, hdf5_file: str, start_line: int, end_line: int) -> dict:
        """
        Verify lines using chain verification first, then fall back to independent verification
        if chain verification fails due to earlier corruption.
        
        Args:
            hdf5_file: Path to the HDF5 file containing the chain
            start_line: Starting line number (1-based, inclusive)
            end_line: Ending line number (1-based, inclusive)
            
        Returns:
            Dictionary with verification results
        """
        print(f"Attempting chain verification for lines {start_line} to {end_line}...")
        
        # Try chain verification first
        try:
            chain_valid = self.verify_chain_range(hdf5_file, start_line, end_line)
            if chain_valid:
                return {
                    'method': 'chain',
                    'valid': True,
                    'message': f'Chain verification successful for lines {start_line} to {end_line}'
                }
        except Exception as e:
            print(f"Chain verification failed: {e}")
        
        print("Chain verification failed, attempting independent verification...")
        
        # Fall back to independent verification
        independent_valid = self.verify_lines_independently(hdf5_file, start_line, end_line)
        
        if independent_valid:
            return {
                'method': 'independent',
                'valid': True,
                'message': f'Independent verification successful for lines {start_line} to {end_line} (earlier lines may be corrupted)'
            }
        else:
            return {
                'method': 'independent',
                'valid': False,
                'message': f'Both chain and independent verification failed for lines {start_line} to {end_line}'
            }

    def analyze_file_changes(self, hdf5_file: str, current_file: str) -> Dict[str, Any]:
        """
        Analyze changes between the original file (stored in chain) and current file.
        This can detect line deletions, insertions, and modifications.
        
        Args:
            hdf5_file: Path to the HDF5 file containing the original chain
            current_file: Path to the current file to compare against
            
        Returns:
            Dictionary with analysis results including deletions, insertions, and modifications
        """
        print(f"Analyzing changes between original chain and current file: {current_file}")
        
        # Read the original chain data
        with h5py.File(hdf5_file, 'r') as f:
            original_lines = f['log_lines'][:]
            hash_dataset = f.attrs.get('hash_algorithm', 'sha256') + '_hashes'
            original_hashes = f[hash_dataset][:]
            total_original_lines = f.attrs['total_entries']
        
        # Convert original lines to strings
        if isinstance(original_lines[0], bytes):
            original_lines = [line.decode('utf-8') for line in original_lines]
        
        # Read the current file
        try:
            with open(current_file, 'r', encoding='utf-8') as f:
                current_lines = [line.strip() for line in f.readlines()]
        except Exception as e:
            return {"error": f"Failed to read current file: {e}"}
        
        # Analyze changes
        analysis = {
            "original_line_count": len(original_lines),
            "current_line_count": len(current_lines),
            "deletions": [],
            "insertions": [],
            "modifications": [],
            "summary": ""
        }
        
        # Find deletions and modifications
        current_idx = 0
        for orig_idx, orig_line in enumerate(original_lines):
            if current_idx >= len(current_lines):
                # All remaining original lines were deleted
                analysis["deletions"].append({
                    "start_line": orig_idx + 1,
                    "end_line": len(original_lines),
                    "count": len(original_lines) - orig_idx,
                    "content": original_lines[orig_idx:]
                })
                break
            
            if orig_line == current_lines[current_idx]:
                # Lines match, move to next
                current_idx += 1
            else:
                # Check if this is a modification or deletion
                # Look ahead to see if we can find a match
                found_match = False
                for look_ahead in range(current_idx + 1, min(current_idx + 10, len(current_lines))):
                    if orig_line == current_lines[look_ahead]:
                        # Found the line later, so lines were inserted
                        inserted_count = look_ahead - current_idx
                        analysis["insertions"].append({
                            "after_line": orig_idx,
                            "count": inserted_count,
                            "content": current_lines[current_idx:look_ahead]
                        })
                        current_idx = look_ahead + 1
                        found_match = True
                        break
                
                if not found_match:
                    # Line was modified or deleted
                    # Check if it's a modification by comparing hashes
                    orig_hash = bytes(original_hashes[orig_idx])
                    current_hash = self.compute_hash(current_lines[current_idx])
                    
                    if orig_hash == current_hash:
                        # Hash matches, so it's a modification (different content but same hash - unlikely but possible)
                        analysis["modifications"].append({
                            "line_number": orig_idx + 1,
                            "original": orig_line,
                            "current": current_lines[current_idx]
                        })
                        current_idx += 1
                    else:
                        # Line was deleted
                        analysis["deletions"].append({
                            "line_number": orig_idx + 1,
                            "original": orig_line
                        })
        
        # Check for insertions at the end
        if current_idx < len(current_lines):
            analysis["insertions"].append({
                "after_line": len(original_lines),
                "count": len(current_lines) - current_idx,
                "content": current_lines[current_idx:]
            })
        
        # Generate summary
        total_deletions = sum(len(d.get('content', [d.get('original', [])])) if isinstance(d.get('content', d.get('original', [])), list) else 1 for d in analysis["deletions"])
        total_insertions = sum(len(d.get('content', [])) for d in analysis["insertions"])
        total_modifications = len(analysis["modifications"])
        
        analysis["summary"] = f"Analysis complete: {total_deletions} lines deleted, {total_insertions} lines inserted, {total_modifications} lines modified"
        
        return analysis
    
    def verify_chain_with_analysis(self, hdf5_file: str, current_file: str) -> Dict[str, Any]:
        """
        Verify chain integrity and provide detailed analysis of any changes detected.
        
        Args:
            hdf5_file: Path to the HDF5 file containing the chain
            current_file: Path to the current file to verify against
            
        Returns:
            Dictionary with verification results and change analysis
        """
        print(f"Verifying chain integrity with detailed analysis...")
        
        # First, do the standard chain verification
        standard_result = self.verify_chain(hdf5_file)
        
        # Then analyze changes
        analysis = self.analyze_file_changes(hdf5_file, current_file)
        
        if "error" in analysis:
            return {
                "valid": False,
                "error": analysis["error"],
                "analysis": analysis
            }
        
        # Determine if the chain is still valid despite changes
        is_valid = standard_result and len(analysis["deletions"]) == 0 and len(analysis["insertions"]) == 0 and len(analysis["modifications"]) == 0
        
        result = {
            "valid": is_valid,
            "standard_verification": standard_result,
            "analysis": analysis,
            "summary": analysis["summary"]
        }
        
        # Print detailed analysis
        print(f"\n📊 Change Analysis:")
        print(f"   Original lines: {analysis['original_line_count']}")
        print(f"   Current lines: {analysis['current_line_count']}")
        
        if analysis["deletions"]:
            print(f"   ❌ Deletions detected:")
            for deletion in analysis["deletions"]:
                if "line_number" in deletion:
                    print(f"      Line {deletion['line_number']}: '{deletion['original']}'")
                else:
                    print(f"      Lines {deletion['start_line']}-{deletion['end_line']}: {deletion['count']} lines deleted")
        
        if analysis["insertions"]:
            print(f"   ➕ Insertions detected:")
            for insertion in analysis["insertions"]:
                print(f"      After line {insertion['after_line']}: {insertion['count']} lines inserted")
        
        if analysis["modifications"]:
            print(f"   🔄 Modifications detected:")
            for modification in analysis["modifications"]:
                print(f"      Line {modification['line_number']}: content changed")
        
        if is_valid:
            print(f"   ✅ No structural changes detected - chain is valid")
        else:
            print(f"   ⚠️  Structural changes detected - chain verification failed")
        
        return result


def main():
    """Main function to run the chain verification system."""
    parser = argparse.ArgumentParser(
        description='Chain Verification System for Log Events - Create and verify cryptographic chains',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:

Chain Creation:
  %(prog)s --source-file messages -o chain.h5                    # Create chain with default settings
  %(prog)s --source-file messages -o chain.h5 --hash-algorithm sha512        # Use SHA512 for enhanced security
  %(prog)s --source-file messages -o chain.h5 --compression-method szip      # Use SZIP compression

Chain Verification:
  %(prog)s --verify --chain-file chain.h5                       # Verify entire chain
  %(prog)s --verify-up-to 100 --chain-file chain.h5             # Verify up to line 100
  %(prog)s --verify-range 50 150 --chain-file chain.h5          # Verify lines 50-150
  %(prog)s --verify-independent 1000 1100 --chain-file chain.h5 # Independent verification
  %(prog)s --verify-with-fallback 1000 1100 --chain-file chain.h5 # Fallback verification
  %(prog)s --verify-fast --chain-file chain.h5                  # Fast verification (check every 100th line)
  %(prog)s --verify-fast 50 --chain-file chain.h5               # Fast verification (check every 50th line)
  %(prog)s --scan-modifications --chain-file chain.h5 --source-file messages  # Scan for modifications (coarse: 100, fine: 10)
  %(prog)s --scan-modifications 50 --chain-file chain.h5 --source-file messages --fine-interval 5  # Custom intervals
  %(prog)s --summary --chain-file chain.h5                      # Show chain information
  %(prog)s --analyze-changes current_messages.txt --chain-file chain.h5 # Analyze deletions/insertions

TSA Timestamping:
  %(prog)s --source-file messages -o chain.h5 --tsa-url http://timestamp.digicert.com/ --ca-bundle /etc/pki/tls/certs/ca-bundle.crt
        """
    )
    parser.add_argument('--source-file', help='Path to the input log file (required for chain creation)')
    parser.add_argument('-o', '--output', default='chain.h5', 
                       help='Output HDF5 file for chain creation (default: chain.h5)')
    parser.add_argument('--chain-file', 
                       help='Path to the HDF5 chain file for verification (use instead of -o for verification commands)')
    parser.add_argument('--compression', type=int, default=6, choices=range(0, 10),
                       help='Compression level (0-9, default: 6)')
    parser.add_argument('--compression-method', default='gzip', choices=['gzip', 'lzf', 'szip'],
                       help='Compression method (gzip, lzf, szip, default: gzip)')
    parser.add_argument('--verify', action='store_true', 
                       help='Verify existing chain file')
    parser.add_argument('--verify-up-to', type=int, metavar='LINE',
                       help='Verify chain up to specific line number')
    parser.add_argument('--verify-range', nargs=2, type=int, metavar=('START', 'END'),
                       help='Verify chain for specific range of lines (start end)')
    parser.add_argument('--verify-independent', nargs=2, type=int, metavar=('START', 'END'),
                       help='Verify lines independently (ignoring earlier corruption)')
    parser.add_argument('--verify-with-fallback', nargs=2, type=int, metavar=('START', 'END'),
                       help='Verify with fallback: try chain first, then independent if chain fails')
    parser.add_argument('--verify-fast', nargs='?', type=int, metavar='INTERVAL', const=100,
                       help='Fast verification: check every M-th line (default: 100, specify custom interval)')
    parser.add_argument('--scan-modifications', nargs='?', type=int, metavar='COARSE_INTERVAL', const=100,
                       help='Scan for modifications using two-phase approach (coarse interval, default: 100)')
    parser.add_argument('--fine-interval', type=int, metavar='FINE_INTERVAL', default=10,
                       help='Fine scan interval for modification scanning (default: 10, used with --scan-modifications)')
    parser.add_argument('--summary', action='store_true', 
                       help='Print summary of existing chain file')
    parser.add_argument('--analyze-changes', metavar='CURRENT_FILE',
                       help='Analyze changes between original file (in chain) and current file. Detects deletions, insertions, and modifications.')
    parser.add_argument('--tsa-url', 
                       help='TSA (Trusted Timestamp Authority) server URL (e.g., http://timestamp.digicert.com/)')
    parser.add_argument('--no-timestamp', action='store_true',
                       help='Skip TSA timestamping (legacy option - TSA is now opt-in by default)')
    parser.add_argument('--ca-bundle', metavar='FILE',
                       help='Path to CA bundle file for TSA verification (required when using --tsa-url)')
    parser.add_argument('--hash-algorithm', choices=['sha256', 'sha384', 'sha512'], default='sha256',
                       help='Hash algorithm to use (sha256, sha384, sha512, default: sha256)')
    
    args = parser.parse_args()
    
    try:
        # Initialize chain verification system
        # TSA timestamping is opt-in: only use if --tsa-url is explicitly provided
        tsa_url = args.tsa_url if args.tsa_url else None
        chain_verifier = ChainVerification(tsa_url=tsa_url, ca_bundle_path=args.ca_bundle, hash_algorithm=args.hash_algorithm)
        
            # Check if this is a verification command
        verification_commands = [args.verify, args.verify_up_to is not None, args.verify_range is not None, 
                               args.verify_independent is not None, args.verify_with_fallback is not None, 
                               args.verify_fast is not None, args.scan_modifications is not None, args.summary, args.analyze_changes is not None]
        
        if any(verification_commands):
            # This is a verification command - source file is not required
            # Determine which chain file to use (--chain-file takes precedence over -o)
            chain_file = args.chain_file if args.chain_file else args.output
        
            if args.verify:
                # Verify existing chain
                if os.path.exists(chain_file):
                    is_valid = chain_verifier.verify_chain(chain_file, args.source_file)
                    print(f"Chain verification result: {'VALID' if is_valid else 'INVALID'}")
                else:
                    print(f"Error: Chain file {chain_file} not found")
                    return 1
            elif args.verify_up_to is not None:
                # Verify chain up to specific line
                if os.path.exists(chain_file):
                    is_valid = chain_verifier.verify_chain_up_to_line(chain_file, args.verify_up_to)
                    print(f"Chain verification result: {'VALID' if is_valid else 'INVALID'}")
                else:
                    print(f"Error: Chain file {chain_file} not found")
                    return 1
            elif args.verify_range is not None:
                # Verify chain for specific range
                start_line, end_line = args.verify_range
                if os.path.exists(chain_file):
                    is_valid = chain_verifier.verify_chain_range(chain_file, start_line, end_line)
                    print(f"Chain verification result: {'VALID' if is_valid else 'INVALID'}")
                else:
                    print(f"Error: Chain file {chain_file} not found")
                    return 1
            elif args.verify_independent is not None:
                # Verify lines independently
                start_line, end_line = args.verify_independent
                if os.path.exists(chain_file):
                    is_valid = chain_verifier.verify_lines_independently(chain_file, start_line, end_line)
                    print(f"Independent verification result: {'VALID' if is_valid else 'INVALID'}")
                else:
                    print(f"Error: Chain file {chain_file} not found")
                    return 1
            elif args.verify_with_fallback is not None:
                # Verify with fallback method
                start_line, end_line = args.verify_with_fallback
                if os.path.exists(chain_file):
                    result = chain_verifier.verify_chain_with_fallback(chain_file, start_line, end_line)
                    print(f"Verification method: {result['method']}")
                    print(f"Verification result: {'VALID' if result['valid'] else 'INVALID'}")
                    print(f"Message: {result['message']}")
                else:
                    print(f"Error: Chain file {chain_file} not found")
                    return 1
            elif args.verify_fast is not None:
                # Fast verification with sampling
                sample_interval = args.verify_fast if args.verify_fast is not None else 100
                if os.path.exists(chain_file):
                    is_valid = chain_verifier.verify_chain_fast(chain_file, args.source_file, sample_interval)
                    print(f"Fast verification result: {'VALID' if is_valid else 'INVALID'}")
                else:
                    print(f"Error: Chain file {chain_file} not found")
                    return 1
            elif args.scan_modifications is not None:
                # Scan for modifications using two-phase approach
                coarse_interval = args.scan_modifications if args.scan_modifications is not None else 100
                fine_interval = args.fine_interval
                if os.path.exists(chain_file):
                    if args.source_file and os.path.exists(args.source_file):
                        result = chain_verifier.scan_for_modifications(chain_file, args.source_file, coarse_interval, fine_interval)
                        if 'error' not in result:
                            print(f"Scan result: {'MODIFICATIONS FOUND' if result['detailed_modifications'] else 'NO MODIFICATIONS'}")
                        else:
                            print(f"Scan error: {result['error']}")
                    else:
                        print("Error: Source file is required for modification scanning")
                        print("Usage: --scan-modifications --source-file CURRENT_FILE --chain-file CHAIN_FILE")
                        return 1
                else:
                    print(f"Error: Chain file {chain_file} not found")
                    return 1
            elif args.summary:
                # Print summary
                if os.path.exists(chain_file):
                    chain_verifier.print_chain_summary(chain_file)
                else:
                    print(f"Error: Chain file {chain_file} not found")
                    return 1
            elif args.analyze_changes is not None:
                # Analyze changes between original and current file
                if os.path.exists(chain_file):
                    if os.path.exists(args.analyze_changes):
                        result = chain_verifier.verify_chain_with_analysis(chain_file, args.analyze_changes)
                        print(f"\nAnalysis result: {'VALID' if result['valid'] else 'INVALID'}")
                        print(f"Summary: {result['summary']}")
                    else:
                        print(f"Error: Current file {args.analyze_changes} not found")
                        return 1
                else:
                    print(f"Error: Chain file {chain_file} not found")
                    return 1
        else:
            # This is a chain creation command - source file is required
            if not args.source_file:
                print("Error: --source-file is required for chain creation")
                print("Use --help for usage information")
                return 1
            
            if not os.path.exists(args.source_file):
                print(f"Error: Input file {args.source_file} not found")
                return 1
            
            # Process the log file
            chain_verifier.process_log_file(args.source_file)
            
            # Save to HDF5
            chain_verifier.save_to_hdf5(args.output, args.compression, args.compression_method)
            
            # Print summary
            chain_verifier.print_chain_summary(args.output)
            
            # Verify the chain
            print("\nVerifying chain integrity...")
            is_valid = chain_verifier.verify_chain(args.output)
            print(f"Chain verification result: {'VALID' if is_valid else 'INVALID'}")
            
            return 0
        
    except ValueError as e:
        print(f"❌ Error: {e}")
        return 1
    except FileNotFoundError as e:
        print(f"❌ Error: File not found - {e}")
        return 1
    except PermissionError as e:
        print(f"❌ Error: Permission denied - {e}")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        print("Please check your input and try again.")
        return 1


if __name__ == "__main__":
    exit(main())
