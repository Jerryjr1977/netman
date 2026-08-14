#project_engine
import json
import os
import logging
import tempfile
import shutil

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


def save_project(file_path, project_data):
    """Save project data to a JSON file atomically using temp file + rename.
    
    Args:
        file_path (str): Target file path
        project_data (dict): Project data to save
        
    Returns:
        tuple: (success: bool, message: str)
    """
    if not file_path:
        logger.error("No file path provided")
        return False, "No file path specified"
    
    if not isinstance(project_data, dict):
        logger.error("Project data must be a dictionary")
        return False, "Invalid data type"
    
    try:
        # Validate data is JSON serializable
        json.dumps(project_data)
    except (TypeError, ValueError) as e:
        logger.error(f"Project data not JSON serializable: {e}")
        return False, f"Serialization error: {e}"
    
    try:
        # Create parent directory if needed
        parent_dir = os.path.dirname(file_path)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir, exist_ok=True)
            logger.debug(f"Created directory: {parent_dir}")
        
        # Atomic write: write to temp file, then rename
        fd, temp_path = tempfile.mkstemp(suffix='.tmp', dir=parent_dir or '.')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(project_data, f, indent=4)
            shutil.move(temp_path, file_path)
            logger.info(f"Project saved: {file_path}")
            return True, "Project saved successfully"
        except Exception as e:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise
            
    except IOError as e:
        logger.error(f"File I/O error: {e}")
        return False, f"I/O error: {e}"
    except Exception as e:
        logger.error(f"Save failed: {e}")
        return False, f"Save error: {e}"


def load_project(file_path):
    """Load project data from a JSON file.
    
    Args:
        file_path (str): Path to project file
        
    Returns:
        tuple: (project_data: dict or None, message: str)
    """
    if not file_path:
        logger.warning("No file path provided")
        return None, "No file path specified"
    
    if not os.path.exists(file_path):
        logger.warning(f"Project file not found: {file_path}")
        return None, "File not found"
    
    if not os.path.isfile(file_path):
        logger.error(f"Path is not a file: {file_path}")
        return None, "Path is not a file"
    
    try:
        # Check file permissions
        if not os.access(file_path, os.R_OK):
            logger.error(f"No read permission: {file_path}")
            return None, "Permission denied"
        
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            logger.warning(f"Project file is empty: {file_path}")
            return None, "File is empty"
        
        logger.debug(f"Loading project from: {file_path} ({file_size} bytes)")
        with open(file_path, 'r', encoding='utf-8') as f:
            project_data = json.load(f)
        
        if not isinstance(project_data, dict):
            logger.error(f"Loaded JSON is not a dictionary")
            return None, "Invalid project format"
        
        logger.info(f"Project loaded: {file_path}")
        return project_data, "Project loaded successfully"
        
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON: {e}")
        return None, f"JSON decode error: {e}"
    except IOError as e:
        logger.error(f"File I/O error: {e}")
        return None, f"I/O error: {e}"
    except Exception as e:
        logger.error(f"Load failed: {e}")
        return None, f"Load error: {e}"