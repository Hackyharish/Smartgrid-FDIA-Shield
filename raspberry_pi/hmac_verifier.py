"""
MODULE BRIEFING:
Purpose: Verifies HMAC-SHA256 signatures on incoming MQTT telemetry payloads for the Smart Grid IoT project.
Inputs: Incoming JSON payloads containing an 'hmac' signature.
Outputs: HMAC validation results indicating whether the payload was tampered with or spoofed.
Dependencies: hmac, hashlib, json, os, logging
Note: The ESP32 signs every JSON payload with a shared secret key. IP-spoofed packets will have invalid/missing HMACs.
"""

import hmac
import hashlib
import json
import os
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Load key from environment or default
HMAC_KEY = os.getenv('HMAC_SECRET_KEY', 'smartgrid_secret_key_2025').encode('utf-8')

def compute_hmac(payload_dict: Dict[str, Any]) -> str:
    """
    Compute HMAC-SHA256 for a payload dict (used for testing/validation).
    Excludes any existing 'hmac' field before computation.
    Returns hex-encoded HMAC string.
    """
    try:
        # Create a copy to avoid modifying the original dictionary
        temp_payload = payload_dict.copy()
        
        # Remove 'hmac' field if it exists
        if 'hmac' in temp_payload:
            del temp_payload['hmac']
            
        # Serialize the remaining dict to canonical JSON
        canonical_json = json.dumps(temp_payload, sort_keys=True, separators=(',', ':'))
        
        # Compute HMAC
        expected_hmac = hmac.new(HMAC_KEY, canonical_json.encode('utf-8'), hashlib.sha256).hexdigest()
        return expected_hmac
    except Exception as e:
        logger.error(f"Error computing HMAC: {e}")
        return ""

def verify_payload_hmac(payload_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts and verifies the HMAC field from an incoming telemetry payload.

    Process:
      1. Make a copy of payload_dict to avoid mutating the original
      2. Pop the 'hmac' field from the copy (save as received_hmac)
      3. Serialize the remaining dict to canonical JSON:
         json.dumps(remaining, sort_keys=True, separators=(',', ':'))
      4. Compute expected HMAC:
         hmac.new(HMAC_KEY, canonical_json.encode(), hashlib.sha256).hexdigest()
      5. Compare using hmac.compare_digest (constant-time)
      6. DO NOT modify the original payload_dict

    Returns:
      {
        'hmac_valid': bool,
        'hmac_received': str or None,
        'hmac_expected': str,
        'hmac_missing': bool
      }
    """
    result = {
        'hmac_valid': False,
        'hmac_received': None,
        'hmac_expected': "",
        'hmac_missing': True
    }

    try:
        if not isinstance(payload_dict, dict):
            logger.error("Payload must be a dictionary to verify HMAC.")
            return result

        # 1. Make a copy of payload_dict to avoid mutating the original
        payload_copy = payload_dict.copy()

        # 2. Pop the 'hmac' field from the copy
        received_hmac = payload_copy.pop('hmac', None)
        result['hmac_received'] = received_hmac
        
        if received_hmac is None or not str(received_hmac).strip():
            result['hmac_missing'] = True
            logger.warning("HMAC field is missing or empty in the payload.")
        else:
            result['hmac_missing'] = False

        # 3. Serialize the remaining dict to canonical JSON
        # 4. Compute expected HMAC
        expected_hmac = compute_hmac(payload_copy)
        result['hmac_expected'] = expected_hmac

        if not expected_hmac:
            logger.error("Failed to compute expected HMAC.")
            return result

        # 5. Compare using hmac.compare_digest (constant-time)
        if received_hmac and hmac.compare_digest(str(received_hmac).lower(), expected_hmac.lower()):
            result['hmac_valid'] = True
        else:
            result['hmac_valid'] = False
            if not result['hmac_missing']:
                logger.warning(f"HMAC mismatch. Expected: {expected_hmac}, Received: {received_hmac}")

    except Exception as e:
        logger.error(f"Error during HMAC verification: {e}")

    return result

def hmac_anomaly_score(hmac_result: Dict[str, Any]) -> float:
    """
    Returns 1.0 if HMAC is invalid or missing (definitive sign of spoofing).
    Returns 0.0 if HMAC is valid.
    Used in the 5-signal detection fusion formula.
    """
    try:
        if hmac_result.get('hmac_valid') is True:
            return 0.0
        return 1.0
    except Exception as e:
        logger.error(f"Error calculating HMAC anomaly score: {e}")
        return 1.0
