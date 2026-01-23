"""
Template Selection Utility Functions for Attendance Certificate Generation

This module provides utility functions for selecting the appropriate PDF template
for attendance certificate generation based on event properties and custom templates.

The template selection follows a priority-based algorithm:
1. Custom template (if valid and accessible)
2. Date-based fallback:
   - Events before 2026-01-01: Legacy template
   - Events from 2026-01-01 onwards: Default template
"""

import os
from datetime import datetime
from typing import Optional, Union
import logging


# Template path constants
LEGACY_TEMPLATE = "static/assets/membrete-constancia-denadoi.pdf"
DEFAULT_TEMPLATE = "static/assets/membrete-css-generico.pdf"
CUTOFF_DATE = datetime(2026, 1, 1)


def validate_template_file(template_path: str) -> bool:
    """
    Validates that a template file exists and is accessible on the filesystem.
    
    Args:
        template_path: String path to the template file
        
    Returns:
        Boolean indicating if the file exists and is accessible
        
    Requirements: 4.4, 7.1
    """
    if not template_path or not template_path.strip():
        return False
    
    try:
        return os.path.exists(template_path) and os.path.isfile(template_path)
    except (OSError, TypeError):
        # Handle file system errors or invalid path types gracefully
        return False


def parse_event_date(fecha_inicio: Union[str, datetime, None]) -> Optional[datetime]:
    """
    Parses event date from various formats into a datetime object.
    
    Handles multiple date formats commonly found in the MongoDB eventos collection:
    - datetime objects (already parsed)
    - ISO format strings: "2025-12-31T23:59:59"
    - Simple date strings: "2025-12-31"
    - Date with time strings: "2025-12-31 23:59:59"
    
    Args:
        fecha_inicio: Event start date in various formats
        
    Returns:
        Parsed datetime object or None if parsing fails
        
    Requirements: 8.1, 8.2, 8.4
    """
    if not fecha_inicio:
        return None
    
    # Already a datetime object
    if isinstance(fecha_inicio, datetime):
        return fecha_inicio
    
    # Handle string dates
    if isinstance(fecha_inicio, str):
        fecha_inicio = fecha_inicio.strip()
        if not fecha_inicio:
            return None
        
        # Common date formats to try
        date_formats = [
            '%Y-%m-%d %H:%M:%S',      # "2025-12-31 23:59:59"
            '%Y-%m-%dT%H:%M:%S',      # "2025-12-31T23:59:59"
            '%Y-%m-%dT%H:%M:%S.%f',   # "2025-12-31T23:59:59.123456"
            '%Y-%m-%d',               # "2025-12-31"
            '%d/%m/%Y',               # "31/12/2025"
            '%d-%m-%Y',               # "31-12-2025"
        ]
        
        for date_format in date_formats:
            try:
                return datetime.strptime(fecha_inicio, date_format)
            except ValueError:
                continue
        
        # If all formats fail, log the issue and return None
        logging.warning(f"Unable to parse date format: {fecha_inicio}")
        return None
    
    # Unsupported type
    logging.warning(f"Unsupported date type: {type(fecha_inicio)}")
    return None


def is_legacy_event(fecha_inicio: Union[str, datetime, None]) -> bool:
    """
    Determines if an event should be classified as legacy based on its start date.
    
    Legacy events are those that started before 2026-01-01 and should use
    the legacy template for backward compatibility.
    
    Args:
        fecha_inicio: Event start date in various formats
        
    Returns:
        True if event is legacy (before 2026-01-01), False otherwise
        
    Requirements: 2.1, 8.1
    """
    parsed_date = parse_event_date(fecha_inicio)
    
    # If date parsing fails, default to modern (non-legacy) behavior
    if parsed_date is None:
        return False
    
    return parsed_date < CUTOFF_DATE


def is_modern_event(fecha_inicio: Union[str, datetime, None]) -> bool:
    """
    Determines if an event should be classified as modern based on its start date.
    
    Modern events are those that started on or after 2026-01-01 and should use
    the default modern template.
    
    Args:
        fecha_inicio: Event start date in various formats
        
    Returns:
        True if event is modern (2026-01-01 or later), False otherwise
        
    Requirements: 3.1, 8.2
    """
    parsed_date = parse_event_date(fecha_inicio)
    
    # If date parsing fails, default to modern behavior
    if parsed_date is None:
        return True
    
    return parsed_date >= CUTOFF_DATE


def get_date_based_template(fecha_inicio: Union[str, datetime, None]) -> str:
    """
    Returns the appropriate template path based on event date classification.
    
    Uses the date-based classification logic to determine whether an event
    should use the legacy or modern template.
    
    Args:
        fecha_inicio: Event start date in various formats
        
    Returns:
        Template path string (LEGACY_TEMPLATE or DEFAULT_TEMPLATE)
        
    Requirements: 2.1, 3.1, 8.1, 8.2, 8.4
    """
    if is_legacy_event(fecha_inicio):
        return LEGACY_TEMPLATE
    else:
        return DEFAULT_TEMPLATE


def determine_template_path(evento: dict) -> str:
    """
    Determines the appropriate template path for an event using priority-based selection.
    
    Priority algorithm:
    1. Custom template (if valid and accessible)
    2. Date-based fallback using enhanced date classification logic
    
    Args:
        evento: Event document from MongoDB containing event details
        
    Returns:
        String path to the appropriate PDF template
        
    Requirements: 4.1, 4.3, 7.1
    """
    # Priority 1: Custom template (if valid)
    custom_template = evento.get('constancia')
    if custom_template and custom_template.strip() and validate_template_file(custom_template):
        return custom_template
    
    # Priority 2: Date-based fallback using enhanced classification
    fecha_inicio = evento.get('fecha_inicio')
    return get_date_based_template(fecha_inicio)


def get_template_constants() -> dict:
    """
    Returns the template path constants for external use.
    
    Returns:
        Dictionary containing template path constants
    """
    return {
        'LEGACY_TEMPLATE': LEGACY_TEMPLATE,
        'DEFAULT_TEMPLATE': DEFAULT_TEMPLATE,
        'CUTOFF_DATE': CUTOFF_DATE
    }