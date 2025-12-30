"""Lightweight PII detection using regex patterns (no heavy dependencies)."""
import re
from typing import List, Dict, Optional


class PIIDetector:
    """Detects Personally Identifiable Information in text using regex patterns."""
    
    # Comprehensive regex patterns for common PII types
    PATTERNS = {
        'EMAIL': re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            re.IGNORECASE
        ),
        'PHONE_US': re.compile(
            r'(\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}|\d{3}[-.\s]?\d{3}[-.\s]?\d{4})'
        ),
        'PHONE_INTERNATIONAL': re.compile(
            r'\+?\d{1,4}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}'
        ),
        'SSN': re.compile(
            r'\b\d{3}-?\d{2}-?\d{4}\b'
        ),
        'CREDIT_CARD': re.compile(
            r'\b\d{4}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}\b'
        ),
        'IP_ADDRESS': re.compile(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ),
        'IBAN': re.compile(
            r'\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b'
        ),
        'CRYPTO_WALLET': re.compile(
            r'\b(0x)?[A-Fa-f0-9]{40,64}\b'
        ),
        'API_KEY': re.compile(
            # Match common API key prefixes (sk-, ghp_, xoxb-, etc.) OR long alphanumeric strings (40+ chars to avoid MD5/session IDs)
            r'\b(?:sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|xoxb-[A-Za-z0-9-]{20,}|[A-Za-z0-9]{40,})\b'
        ),
    }
    
    def __init__(self):
        """Initialize the lightweight PII detector."""
        pass
    
    def contains_sensitive_data(self, text: str) -> bool:
        """Check if text contains sensitive PII data.
        
        Args:
            text: The text to analyze
            
        Returns:
            True if PII is detected, False otherwise
        """
        try:
            return len(self.get_detected_entities(text)) > 0
        except Exception as e:
            # Fail-closed: If detection fails, assume PII is present (safer default)
            print(f"PII detection error (failing closed): {e}")
            return True
    
    def get_detected_entities(self, text: str) -> List[Dict]:
        """Get detailed information about detected PII entities.
        
        Args:
            text: The text to analyze
            
        Returns:
            List of dictionaries containing entity type, start, end, and score
        """
        try:
            entities = []
            
            for entity_type, pattern in self.PATTERNS.items():
                for match in pattern.finditer(text):
                    # Validate matches to reduce false positives
                    matched_text = match.group(0)
                    if self._validate_match(entity_type, matched_text):
                        entities.append({
                            'entity_type': entity_type,
                            'start': match.start(),
                            'end': match.end(),
                            'score': 0.9,  # High confidence for regex matches
                            'text': matched_text
                        })
            
            # Remove overlapping entities (keep the longest match)
            entities = self._remove_overlaps(entities)
            
            return entities
        except Exception as e:
            # Fail-closed: If detection fails, return a generic PII detection
            print(f"PII entity detection error (failing closed): {e}")
            return [{
                'entity_type': 'UNKNOWN',
                'start': 0,
                'end': len(text),
                'score': 1.0,
                'text': text[:50] + '...' if len(text) > 50 else text
            }]
    
    def _validate_match(self, entity_type: str, matched_text: str) -> bool:
        """Validate if a regex match is likely a real PII entity.
        
        Args:
            entity_type: Type of entity
            matched_text: The matched text
            
        Returns:
            True if match is likely valid, False otherwise
        """
        # Additional validation for specific entity types
        if entity_type == 'EMAIL':
            # Check for common false positives
            if matched_text.endswith('.png') or matched_text.endswith('.jpg'):
                return False
            # Email should have @ symbol
            return '@' in matched_text
        
        elif entity_type == 'PHONE_US':
            # Remove formatting and check length
            digits = re.sub(r'\D', '', matched_text)
            return len(digits) == 10
        
        elif entity_type == 'SSN':
            # SSN should be exactly 9 digits
            digits = re.sub(r'\D', '', matched_text)
            # Check for invalid SSN patterns (000-xx-xxxx, xxx-00-xxxx, etc.)
            parts = matched_text.split('-') if '-' in matched_text else [matched_text]
            if len(parts) == 3:
                if parts[0] == '000' or parts[1] == '00':
                    return False
            return len(digits) == 9
        
        elif entity_type == 'CREDIT_CARD':
            # Remove formatting and validate with Luhn algorithm
            digits = re.sub(r'\D', '', matched_text)
            if len(digits) < 13 or len(digits) > 19:
                return False
            # Validate using Luhn algorithm
            return self._luhn_check(digits)
        
        elif entity_type == 'IP_ADDRESS':
            # Validate IP range
            parts = matched_text.split('.')
            if len(parts) != 4:
                return False
            try:
                return all(0 <= int(part) <= 255 for part in parts)
            except ValueError:
                return False
        
        elif entity_type == 'PHONE_INTERNATIONAL':
            # International phone must start with + or have minimum 8 digits
            digits = re.sub(r'\D', '', matched_text)
            if matched_text.startswith('+'):
                return len(digits) >= 8  # Minimum for international
            # If no +, require more digits to avoid false positives
            return len(digits) >= 10
        
        elif entity_type == 'API_KEY':
            # Additional validation: check if it matches known prefixes or is long enough
            if matched_text.startswith(('sk-', 'ghp_', 'xoxb-')):
                return True
            # For generic long strings, ensure it's at least 40 chars (avoids MD5 hashes)
            return len(matched_text) >= 40
        
        return True
    
    def _luhn_check(self, card_number: str) -> bool:
        """Validate credit card number using Luhn algorithm.
        
        Args:
            card_number: Credit card number as string (digits only)
            
        Returns:
            True if card number passes Luhn check, False otherwise
        """
        try:
            # Reverse the card number
            reversed_digits = card_number[::-1]
            
            # Calculate sum
            total = 0
            for i, digit in enumerate(reversed_digits):
                num = int(digit)
                if i % 2 == 1:  # Every second digit (from right)
                    num *= 2
                    if num > 9:
                        num -= 9  # Sum of digits for two-digit numbers
                total += num
            
            # Valid if total is divisible by 10
            return total % 10 == 0
        except (ValueError, IndexError):
            return False
    
    def _remove_overlaps(self, entities: List[Dict]) -> List[Dict]:
        """Remove overlapping entities, keeping the longest match.
        
        Args:
            entities: List of detected entities
            
        Returns:
            List with overlapping entities removed
        """
        if not entities:
            return entities
        
        # Sort by start position
        entities.sort(key=lambda x: x['start'])
        
        non_overlapping = []
        for entity in entities:
            # Check if this entity overlaps with any already added
            overlaps = False
            for added in non_overlapping:
                if not (entity['end'] <= added['start'] or entity['start'] >= added['end']):
                    # They overlap - keep the longer one
                    if (entity['end'] - entity['start']) > (added['end'] - added['start']):
                        non_overlapping.remove(added)
                        non_overlapping.append(entity)
                    overlaps = True
                    break
            
            if not overlaps:
                non_overlapping.append(entity)
        
        return non_overlapping
    
    def get_entity_summary(self, text: str) -> str:
        """Get a human-readable summary of detected entities.
        
        Args:
            text: The text to analyze
            
        Returns:
            Summary string of detected entities
        """
        entities = self.get_detected_entities(text)
        
        if not entities:
            return "No PII detected"
        
        entity_types = {}
        for entity in entities:
            entity_type = entity['entity_type']
            if entity_type not in entity_types:
                entity_types[entity_type] = 0
            entity_types[entity_type] += 1
        
        summary_parts = [f"{count} {entity_type}(s)" for entity_type, count in entity_types.items()]
        return f"Detected: {', '.join(summary_parts)}"


# Global detector instance (lazy initialization to avoid mutex issues with --reload)
_pii_detector_instance = None

def get_pii_detector():
    """Get or create the global PII detector instance."""
    global _pii_detector_instance
    if _pii_detector_instance is None:
        _pii_detector_instance = PIIDetector()
    return _pii_detector_instance

# For backward compatibility
pii_detector = None

