"""
Core file utilities.

This module provides pure file manipulation functions with no external dependencies
beyond standard Python libraries. These functions form the foundation of the
modular utilities architecture.

Key principles:
1. Pure functions with no side effects
2. No external dependencies beyond standard library
3. No imports from other reNgine modules
4. Stateless and thread-safe
5. Easy to test and reuse
"""

import glob
import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


def get_file_extension(filename: str) -> str:
    """
    Get file extension from filename.
    
    Args:
        filename: Filename to get extension from
        
    Returns:
        File extension (without dot)
    """
    return Path(filename).suffix.lstrip('.')


def get_filename_without_extension(filename: str) -> str:
    """
    Get filename without extension.
    
    Args:
        filename: Filename to process
        
    Returns:
        Filename without extension
    """
    return Path(filename).stem


def get_file_directory(filename: str) -> str:
    """
    Get directory path from filename.
    
    Args:
        filename: Filename to get directory from
        
    Returns:
        Directory path
    """
    return str(Path(filename).parent)


def get_file_basename(filename: str) -> str:
    """
    Get basename from filename.
    
    Args:
        filename: Filename to get basename from
        
    Returns:
        Basename
    """
    return Path(filename).name


def join_path(*parts: str) -> str:
    """
    Join path parts safely.
    
    Args:
        *parts: Path parts to join
        
    Returns:
        Joined path
    """
    return str(Path(*parts))


def normalize_path(path: str) -> str:
    """
    Normalize path by resolving .. and . components.
    
    Args:
        path: Path to normalize
        
    Returns:
        Normalized path
    """
    return str(Path(path).resolve())


def is_absolute_path(path: str) -> bool:
    """
    Check if path is absolute.
    
    Args:
        path: Path to check
        
    Returns:
        True if path is absolute
    """
    return Path(path).is_absolute()


def is_relative_path(path: str) -> bool:
    """
    Check if path is relative.
    
    Args:
        path: Path to check
        
    Returns:
        True if path is relative
    """
    return not Path(path).is_absolute()


def get_relative_path(path: str, base: str) -> str:
    """
    Get relative path from base.
    
    Args:
        path: Target path
        base: Base path
        
    Returns:
        Relative path
    """
    return str(Path(path).relative_to(base))


def get_absolute_path(path: str) -> str:
    """
    Get absolute path.
    
    Args:
        path: Path to convert
        
    Returns:
        Absolute path
    """
    return str(Path(path).resolve())


def create_temp_file(content: str = "", suffix: str = "", prefix: str = "tmp", 
                    directory: Optional[str] = None) -> str:
    """
    Create temporary file with optional content.
    
    Args:
        content: Content to write to file
        suffix: File suffix
        prefix: File prefix
        directory: Directory to create file in
        
    Returns:
        Path to temporary file
    """
    fd, path = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=directory)
    try:
        if content:
            with os.fdopen(fd, 'w') as f:
                f.write(content)
        else:
            os.close(fd)
    except Exception:
        os.close(fd)
        raise
    return path


def create_temp_directory(suffix: str = "", prefix: str = "tmp", 
                         directory: Optional[str] = None) -> str:
    """
    Create temporary directory.
    
    Args:
        suffix: Directory suffix
        prefix: Directory prefix
        directory: Parent directory
        
    Returns:
        Path to temporary directory
    """
    return tempfile.mkdtemp(suffix=suffix, prefix=prefix, dir=directory)


def file_exists(filepath: str) -> bool:
    """
    Check if file exists.
    
    Args:
        filepath: Path to file
        
    Returns:
        True if file exists
    """
    return os.path.isfile(filepath)


def get_file_size(filepath: str) -> int:
    """
    Get file size in bytes.
    
    Args:
        filepath: Path to file
        
    Returns:
        File size in bytes, or 0 if file doesn't exist
    """
    try:
        return os.path.getsize(filepath)
    except (OSError, FileNotFoundError):
        return 0


def get_file_hash(filepath: str, algorithm: str = "md5") -> str:
    """
    Get file hash.
    
    Args:
        filepath: Path to file
        algorithm: Hash algorithm (md5, sha1, sha256)
        
    Returns:
        File hash, or empty string if file doesn't exist
    """
    try:
        hash_obj = hashlib.new(algorithm)
        
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    except (OSError, FileNotFoundError):
        return ""


def read_file_lines(filepath: str, encoding: str = 'utf-8') -> List[str]:
    """
    Read file lines.
    
    Args:
        filepath: Path to file
        encoding: File encoding
        
    Returns:
        List of lines
    """
    with open(filepath, 'r', encoding=encoding) as f:
        return f.readlines()


def read_file_content(filepath: str, encoding: str = 'utf-8') -> str:
    """
    Read file content.
    
    Args:
        filepath: Path to file
        encoding: File encoding
        
    Returns:
        File content, or empty string if file doesn't exist
    """
    try:
        with open(filepath, 'r', encoding=encoding) as f:
            return f.read()
    except (OSError, FileNotFoundError):
        return ""


def read_file_binary(filepath: str) -> bytes:
    """
    Read file as binary.
    
    Args:
        filepath: Path to file
        
    Returns:
        File content as bytes
    """
    with open(filepath, 'rb') as f:
        return f.read()


def write_file_content(filepath: str, content: str, encoding: str = 'utf-8') -> bool:
    """
    Write content to file.
    
    Args:
        filepath: Path to file
        content: Content to write
        encoding: File encoding
        
    Returns:
        True if successful, False otherwise
    """
    try:
        with open(filepath, 'w', encoding=encoding) as f:
            f.write(content)
        return True
    except (OSError, IOError):
        return False


def write_file_binary(filepath: str, content: bytes) -> None:
    """
    Write binary content to file.
    
    Args:
        filepath: Path to file
        content: Binary content to write
    """
    with open(filepath, 'wb') as f:
        f.write(content)


def append_file_content(filepath: str, content: str, encoding: str = 'utf-8') -> None:
    """
    Append content to file.
    
    Args:
        filepath: Path to file
        content: Content to append
        encoding: File encoding
    """
    with open(filepath, 'a', encoding=encoding) as f:
        f.write(content)


def read_json_file(filepath: str, encoding: str = 'utf-8') -> Any:
    """
    Read JSON file.
    
    Args:
        filepath: Path to JSON file
        encoding: File encoding
        
    Returns:
        Parsed JSON data
    """
    with open(filepath, 'r', encoding=encoding) as f:
        return json.load(f)


def write_json_file(filepath: str, data: Any, indent: int = 2, 
                   encoding: str = 'utf-8') -> None:
    """
    Write data to JSON file.
    
    Args:
        filepath: Path to JSON file
        data: Data to write
        indent: JSON indentation
        encoding: File encoding
    """
    with open(filepath, 'w', encoding=encoding) as f:
        json.dump(data, f, indent=indent, ensure_ascii=False, default=str)


def read_csv_file(filepath: str, encoding: str = 'utf-8') -> List[List[str]]:
    """
    Read CSV file.
    
    Args:
        filepath: Path to CSV file
        encoding: File encoding
        
    Returns:
        List of rows (each row is a list of values)
    """
    rows = []
    with open(filepath, 'r', encoding=encoding) as f:
        for line in f:
            # Simple CSV parsing (doesn't handle quoted values with commas)
            row = [cell.strip() for cell in line.strip().split(',')]
            rows.append(row)
    return rows


def write_csv_file(filepath: str, data: List[List[str]], 
                  encoding: str = 'utf-8') -> None:
    """
    Write data to CSV file.
    
    Args:
        filepath: Path to CSV file
        data: Data to write (list of rows)
        encoding: File encoding
    """
    with open(filepath, 'w', encoding=encoding) as f:
        for row in data:
            f.write(','.join(str(cell) for cell in row) + '\n')


def read_text_file_lines(filepath: str, encoding: str = 'utf-8') -> List[str]:
    """
    Read text file lines (stripped).
    
    Args:
        filepath: Path to text file
        encoding: File encoding
        
    Returns:
        List of lines (stripped)
    """
    with open(filepath, 'r', encoding=encoding) as f:
        return [line.strip() for line in f if line.strip()]


def write_text_file_lines(filepath: str, lines: List[str], 
                         encoding: str = 'utf-8') -> None:
    """
    Write lines to text file.
    
    Args:
        filepath: Path to text file
        lines: Lines to write
        encoding: File encoding
    """
    with open(filepath, 'w', encoding=encoding) as f:
        for line in lines:
            f.write(line + '\n')


def append_text_file_lines(filepath: str, lines: List[str], 
                          encoding: str = 'utf-8') -> None:
    """
    Append lines to text file.
    
    Args:
        filepath: Path to text file
        lines: Lines to append
        encoding: File encoding
    """
    with open(filepath, 'a', encoding=encoding) as f:
        for line in lines:
            f.write(line + '\n')


def search_in_file(filepath: str, pattern: str, encoding: str = 'utf-8') -> List[str]:
    """
    Search for pattern in file.
    
    Args:
        filepath: Path to file
        pattern: Regex pattern to search
        encoding: File encoding
        
    Returns:
        List of matching lines
    """
    matches = []
    regex = re.compile(pattern)
    
    with open(filepath, 'r', encoding=encoding) as f:
        for line_num, line in enumerate(f, 1):
            if regex.search(line):
                matches.append(f"{line_num}: {line.strip()}")
    
    return matches


def replace_in_file(filepath: str, pattern: str, replacement: str, 
                   encoding: str = 'utf-8') -> int:
    """
    Replace pattern in file.
    
    Args:
        filepath: Path to file
        pattern: Regex pattern to replace
        replacement: Replacement string
        encoding: File encoding
        
    Returns:
        Number of replacements made
    """
    regex = re.compile(pattern)
    replacements = 0
    
    # Read file
    with open(filepath, 'r', encoding=encoding) as f:
        content = f.read()
    
    # Replace
    new_content, count = regex.subn(replacement, content)
    replacements = count
    
    # Write back if changes were made
    if replacements > 0:
        with open(filepath, 'w', encoding=encoding) as f:
            f.write(new_content)
    
    return replacements


def copy_file(src: str, dst: str) -> None:
    """
    Copy file.
    
    Args:
        src: Source file path
        dst: Destination file path
    """
    import shutil
    shutil.copy2(src, dst)


def move_file(src: str, dst: str) -> None:
    """
    Move file.
    
    Args:
        src: Source file path
        dst: Destination file path
    """
    import shutil
    shutil.move(src, dst)


def delete_file(filepath: str) -> bool:
    """
    Delete file.
    
    Args:
        filepath: Path to file to delete
        
    Returns:
        True if successful, False otherwise
    """
    try:
        os.remove(filepath)
        return True
    except (OSError, FileNotFoundError):
        return False


def create_directory(dirpath: str) -> None:
    """
    Create directory.
    
    Args:
        dirpath: Path to directory to create
    """
    os.makedirs(dirpath, exist_ok=True)


def delete_directory(dirpath: str) -> None:
    """
    Delete directory.
    
    Args:
        dirpath: Path to directory to delete
    """
    import shutil
    shutil.rmtree(dirpath)


def list_directory(dirpath: str, include_hidden: bool = False) -> List[str]:
    """
    List directory contents.
    
    Args:
        dirpath: Path to directory
        include_hidden: Include hidden files
        
    Returns:
        List of filenames
    """
    items = os.listdir(dirpath)
    if not include_hidden:
        items = [item for item in items if not item.startswith('.')]
    return items


def list_files(dirpath: str, pattern: Optional[str] = None, 
              include_hidden: bool = False) -> List[str]:
    """
    List files in directory.
    
    Args:
        dirpath: Path to directory
        pattern: Regex pattern to match filenames
        include_hidden: Include hidden files
        
    Returns:
        List of file paths
    """
    files = []
    for item in os.listdir(dirpath):
        if not include_hidden and item.startswith('.'):
            continue
        
        item_path = os.path.join(dirpath, item)
        if os.path.isfile(item_path):
            if pattern is None or re.match(pattern, item):
                files.append(item_path)
    
    return files


def list_directories(dirpath: str, include_hidden: bool = False) -> List[str]:
    """
    List directories in directory.
    
    Args:
        dirpath: Path to directory
        include_hidden: Include hidden directories
        
    Returns:
        List of directory paths
    """
    directories = []
    for item in os.listdir(dirpath):
        if not include_hidden and item.startswith('.'):
            continue
        
        item_path = os.path.join(dirpath, item)
        if os.path.isdir(item_path):
            directories.append(item_path)
    
    return directories


def find_files(dirpath: str, pattern: str, recursive: bool = True) -> List[str]:
    """
    Find files matching pattern.
    
    Args:
        dirpath: Directory to search
        pattern: Regex pattern to match
        recursive: Search recursively
        
    Returns:
        List of matching file paths
    """
    files = []
    regex = re.compile(pattern)
    
    if recursive:
        for root, dirs, filenames in os.walk(dirpath):
            for filename in filenames:
                if regex.search(filename):
                    files.append(os.path.join(root, filename))
    else:
        for filename in os.listdir(dirpath):
            if regex.search(filename):
                files.append(os.path.join(dirpath, filename))
    
    return files


def get_file_info(filepath: str) -> Dict[str, Any]:
    """
    Get file information.
    
    Args:
        filepath: Path to file
        
    Returns:
        Dictionary with file information
    """
    stat = os.stat(filepath)
    return {
        'path': filepath,
        'size': stat.st_size,
        'modified': stat.st_mtime,
        'created': stat.st_ctime,
        'accessed': stat.st_atime,
        'is_file': os.path.isfile(filepath),
        'is_dir': os.path.isdir(filepath),
        'is_link': os.path.islink(filepath),
        'extension': get_file_extension(filepath),
        'basename': get_file_basename(filepath),
        'dirname': get_file_directory(filepath)
    }


def ensure_directory_exists(dirpath: str) -> None:
    """
    Ensure directory exists, create if it doesn't.
    
    Args:
        dirpath: Path to directory
    """
    os.makedirs(dirpath, exist_ok=True)


def ensure_file_directory_exists(filepath: str) -> None:
    """
    Ensure file's directory exists, create if it doesn't.
    
    Args:
        filepath: Path to file
    """
    directory = get_file_directory(filepath)
    ensure_directory_exists(directory)


def get_common_file_extensions() -> Dict[str, List[str]]:
    """
    Get common file extensions by category.
    
    Returns:
        Dictionary mapping categories to extensions
    """
    return {
        'images': ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'svg', 'webp', 'ico'],
        'videos': ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm', 'm4v'],
        'audio': ['mp3', 'wav', 'flac', 'aac', 'ogg', 'wma', 'm4a'],
        'documents': ['pdf', 'doc', 'docx', 'txt', 'rtf', 'odt', 'pages'],
        'spreadsheets': ['xls', 'xlsx', 'csv', 'ods', 'numbers'],
        'presentations': ['ppt', 'pptx', 'odp', 'key'],
        'archives': ['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz'],
        'code': ['py', 'js', 'html', 'css', 'java', 'cpp', 'c', 'php', 'rb', 'go'],
        'data': ['json', 'xml', 'yaml', 'yml', 'toml', 'ini', 'cfg', 'conf'],
        'executables': ['exe', 'msi', 'deb', 'rpm', 'dmg', 'app', 'bin']
    }


def is_image_file(filename: str) -> bool:
    """
    Check if file is an image.
    
    Args:
        filename: Filename to check
        
    Returns:
        True if file is an image
    """
    ext = get_file_extension(filename).lower()
    return ext in get_common_file_extensions()['images']


def is_video_file(filename: str) -> bool:
    """
    Check if file is a video.
    
    Args:
        filename: Filename to check
        
    Returns:
        True if file is a video
    """
    ext = get_file_extension(filename).lower()
    return ext in get_common_file_extensions()['videos']


def is_audio_file(filename: str) -> bool:
    """
    Check if file is an audio file.
    
    Args:
        filename: Filename to check
        
    Returns:
        True if file is an audio file
    """
    ext = get_file_extension(filename).lower()
    return ext in get_common_file_extensions()['audio']


def is_document_file(filename: str) -> bool:
    """
    Check if file is a document.
    
    Args:
        filename: Filename to check
        
    Returns:
        True if file is a document
    """
    ext = get_file_extension(filename).lower()
    return ext in get_common_file_extensions()['documents']


def is_archive_file(filename: str) -> bool:
    """
    Check if file is an archive.
    
    Args:
        filename: Filename to check
        
    Returns:
        True if file is an archive
    """
    ext = get_file_extension(filename).lower()
    return ext in get_common_file_extensions()['archives']


def is_code_file(filename: str) -> bool:
    """
    Check if file is a code file.
    
    Args:
        filename: Filename to check
        
    Returns:
        True if file is a code file
    """
    ext = get_file_extension(filename).lower()
    return ext in get_common_file_extensions()['code']


def is_data_file(filename: str) -> bool:
    """
    Check if file is a data file.
    
    Args:
        filename: Filename to check
        
    Returns:
        True if file is a data file
    """
    ext = get_file_extension(filename).lower()
    return ext in get_common_file_extensions()['data']


def get_file_type(filename: str) -> str:
    """
    Get file type category.
    
    Args:
        filename: Filename to check
        
    Returns:
        File type category
    """
    ext = get_file_extension(filename).lower()
    
    for category, extensions in get_common_file_extensions().items():
        if ext in extensions:
            return category
    
    return 'unknown'


def remove_file_or_pattern(path: str, pattern: Optional[str] = None) -> bool:
    """
    Safely remove a file/directory or pattern matching files.
    
    Args:
        path: Path to file/directory to remove
        pattern: Optional pattern for multiple files (e.g. "*.csv")
        
    Returns:
        bool: True if successful, False if error occurred
        
    Example:
        >>> remove_file_or_pattern("/tmp/file.txt")
        True
        >>> remove_file_or_pattern("/tmp", "*.log")
        True
    """
    try:
        if pattern:
            # Find and remove files matching the pattern
            matched_files = glob.glob(os.path.join(path, pattern))
            if not matched_files:
                return True  # No files to remove is not an error

            all_deleted = True
            for file_path in matched_files:
                try:
                    if os.path.isfile(file_path):
                        os.remove(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except OSError:
                    all_deleted = False
                    
            return all_deleted
        else:
            # Remove single file or directory
            if os.path.isfile(path):
                os.remove(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)
            else:
                return True  # Path doesn't exist, not an error
                
            return True
            
    except OSError:
        return False
