import asyncio
import logging
import os
import re
import pathlib
import pymssql
from mcp.server import Server
from mcp.types import Resource, Tool, TextContent
from pydantic import AnyUrl

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("mssql_mcp_server")

# Allowed directories for SQL file execution
ALLOWED_SQL_DIRS = [
    "/workspace/sql",
    "./sql",
    "sql",
]

def validate_table_name(table_name: str) -> str:
    """Validate and escape table name to prevent SQL injection."""
    # Allow only alphanumeric, underscore, and dot (for schema.table)
    if not re.match(r'^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+)?$', table_name):
        raise ValueError(f"Invalid table name: {table_name}")
    
    # Split schema and table if present
    parts = table_name.split('.')
    if len(parts) == 2:
        # Escape both schema and table name
        return f"[{parts[0]}].[{parts[1]}]"
    else:
        # Just table name
        return f"[{table_name}]"

def get_db_config():
    """Get database configuration from environment variables."""
    # Basic configuration
    server = os.getenv("MSSQL_SERVER", "localhost")
    logger.info(f"MSSQL_SERVER environment variable: {os.getenv('MSSQL_SERVER', 'NOT SET')}")
    logger.info(f"Using server: {server}")
    
    # Handle LocalDB connections (Issue #6)
    # LocalDB format: (localdb)\instancename
    if server.startswith("(localdb)\\"):
        # For LocalDB, pymssql needs special formatting
        # Convert (localdb)\MSSQLLocalDB to localhost\MSSQLLocalDB with dynamic port
        instance_name = server.replace("(localdb)\\", "")
        server = f".\\{instance_name}"
        logger.info(f"Detected LocalDB connection, converted to: {server}")
    
    config = {
        "server": server,
        "user": os.getenv("MSSQL_USER"),
        "password": os.getenv("MSSQL_PASSWORD"),
        "database": os.getenv("MSSQL_DATABASE"),
        "port": os.getenv("MSSQL_PORT", "1433"),  # Default MSSQL port
    }    
    # Port support (Issue #8)
    port = os.getenv("MSSQL_PORT")
    if port:
        try:
            config["port"] = int(port)
        except ValueError:
            logger.warning(f"Invalid MSSQL_PORT value: {port}. Using default port.")
    
    # Encryption settings for Azure SQL (Issue #11)
    # Check if we're connecting to Azure SQL
    if config["server"] and ".database.windows.net" in config["server"]:
        config["tds_version"] = "7.4"  # Required for Azure SQL
        # Azure SQL requires encryption - use connection string format for pymssql 2.3+
        # This improves upon TDS-only approach by being more explicit
        if os.getenv("MSSQL_ENCRYPT", "true").lower() == "true":
            config["server"] += ";Encrypt=yes;TrustServerCertificate=no"
    else:
        # For non-Azure connections, respect the MSSQL_ENCRYPT setting
        # Use connection string format in addition to TDS version for better compatibility
        encrypt_str = os.getenv("MSSQL_ENCRYPT", "false")
        if encrypt_str.lower() == "true":
            config["tds_version"] = "7.4"  # Keep existing TDS approach
            config["server"] += ";Encrypt=yes;TrustServerCertificate=yes"  # Add explicit setting
            
    # Windows Authentication support (Issue #7)
    use_windows_auth = os.getenv("MSSQL_WINDOWS_AUTH", "false").lower() == "true"
    
    if use_windows_auth:
        # For Windows authentication, user and password are not required
        if not config["database"]:
            logger.error("MSSQL_DATABASE is required")
            raise ValueError("Missing required database configuration")
        # Remove user and password for Windows auth
        config.pop("user", None)
        config.pop("password", None)
        logger.info("Using Windows Authentication")
    else:
        # SQL Authentication - user and password are required
        if not all([config["user"], config["password"], config["database"]]):
            logger.error("Missing required database configuration. Please check environment variables:")
            logger.error("MSSQL_USER, MSSQL_PASSWORD, and MSSQL_DATABASE are required")
            raise ValueError("Missing required database configuration")
    
    return config

def get_command():
    """Get the command to execute SQL queries."""
    return os.getenv("MSSQL_COMMAND", "execute_sql")

def is_select_query(query: str) -> bool:
    """
    Check if a query is a SELECT statement, accounting for comments.
    Handles both single-line (--) and multi-line (/* */) SQL comments.
    """
    # Remove multi-line comments /* ... */
    query_cleaned = re.sub(r'/\*.*?\*/', '', query, flags=re.DOTALL)
    
    # Remove single-line comments -- ...
    lines = query_cleaned.split('\n')
    cleaned_lines = []
    for line in lines:
        # Find -- comment marker and remove everything after it
        comment_pos = line.find('--')
        if comment_pos != -1:
            line = line[:comment_pos]
        cleaned_lines.append(line)
    
    query_cleaned = '\n'.join(cleaned_lines)
    
    # Get the first non-empty word after stripping whitespace
    first_word = query_cleaned.strip().split()[0] if query_cleaned.strip() else ""
    return first_word.upper() == "SELECT"


def validate_sql_file_path(file_path: str) -> str:
    """
    Validate that the SQL file path is within allowed directories.
    Prevents arbitrary file read vulnerabilities.
    """
    # Resolve to absolute path
    resolved_path = pathlib.Path(file_path).resolve()
    
    # Check if path exists first (for better error message)
    if not resolved_path.exists():
        raise FileNotFoundError(f"SQL file not found: {file_path}")
    
    # Verify it's a file (not a directory)
    if not resolved_path.is_file():
        raise ValueError(f"Path is not a file: {file_path}")
    
    # Verify file extension is .sql
    if resolved_path.suffix.lower() != '.sql':
        raise ValueError(f"File must have .sql extension: {file_path}")
    
    # Check if path is within any allowed directory
    for allowed_dir in ALLOWED_SQL_DIRS:
        try:
            allowed_resolved = pathlib.Path(allowed_dir).resolve()
            # Check if the file path starts with the allowed directory
            if str(resolved_path).startswith(str(allowed_resolved)):
                return str(resolved_path)
        except Exception:
            continue
    
    raise ValueError(
        f"SQL file path must be within allowed directories: {ALLOWED_SQL_DIRS}. "
        f"Got: {file_path}"
    )


def split_sql_statements(sql_content: str) -> list[str]:
    """
    Split SQL content into individual statements.
    Handles multiple statements separated by semicolons (even on same line).
    Preserves statements that contain GO batches (common in SQL Server).
    """
    statements = []
    
    # First, normalize the content by handling GO batch separators
    # GO must be on its own line to be recognized as a batch separator
    lines = sql_content.split('\n')
    normalized_lines = []
    current_batch = []
    
    for line in lines:
        stripped_line = line.strip()
        
        # Handle GO batch separator (SQL Server specific) - must be on its own line
        if stripped_line.upper() == 'GO':
            if current_batch:
                normalized_lines.append('\n'.join(current_batch))
                current_batch = []
            continue
        
        current_batch.append(line)
    
    if current_batch:
        normalized_lines.append('\n'.join(current_batch))
    
    # Now process each batch for semicolon-separated statements
    for batch in normalized_lines:
        # Split by semicolon, but handle multi-line statements
        remaining = batch
        while remaining:
            # Find the first semicolon
            semi_pos = remaining.find(';')
            if semi_pos == -1:
                # No more semicolons, add remaining as final statement
                stmt = remaining.strip()
                if stmt and not stmt.startswith('--'):
                    statements.append(stmt)
                break
            else:
                # Extract statement up to and including semicolon
                stmt = remaining[:semi_pos + 1].strip()
                if stmt and not stmt.startswith('--'):
                    statements.append(stmt)
                remaining = remaining[semi_pos + 1:]
    
    return statements

# Initialize server
app = Server("mssql_mcp_server")

@app.list_resources()
async def list_resources() -> list[Resource]:
    """List SQL Server tables as resources."""
    config = get_db_config()
    try:
        conn = pymssql.connect(**config)
        cursor = conn.cursor()
        # Query to get user tables from the current database
        cursor.execute("""
            SELECT TABLE_NAME 
            FROM INFORMATION_SCHEMA.TABLES 
            WHERE TABLE_TYPE = 'BASE TABLE'
        """)
        tables = cursor.fetchall()
        logger.info(f"Found tables: {tables}")
        
        resources = []
        for table in tables:
            resources.append(
                Resource(
                    uri=f"mssql://{table[0]}/data",
                    name=f"Table: {table[0]}",
                    mimeType="text/plain",
                    description=f"Data in table: {table[0]}"
                )
            )
        cursor.close()
        conn.close()
        return resources
    except Exception as e:
        logger.error(f"Failed to list resources: {str(e)}")
        return []

@app.read_resource()
async def read_resource(uri: AnyUrl) -> str:
    """Read table contents."""
    config = get_db_config()
    uri_str = str(uri)
    logger.info(f"Reading resource: {uri_str}")
    
    if not uri_str.startswith("mssql://"):
        raise ValueError(f"Invalid URI scheme: {uri_str}")
        
    parts = uri_str[8:].split('/')
    table = parts[0]
    
    try:
        # Validate table name to prevent SQL injection
        safe_table = validate_table_name(table)
        
        conn = pymssql.connect(**config)
        cursor = conn.cursor()
        # Use TOP 100 for MSSQL (equivalent to LIMIT in MySQL)
        cursor.execute(f"SELECT TOP 100 * FROM {safe_table}")
        columns = [desc[0] for desc in cursor.description]
        rows = cursor.fetchall()
        result = [",".join(map(str, row)) for row in rows]
        cursor.close()
        conn.close()
        return "\n".join([",".join(columns)] + result)
                
    except Exception as e:
        logger.error(f"Database error reading resource {uri}: {str(e)}")
        raise RuntimeError(f"Database error: {str(e)}")

@app.list_tools()
async def list_tools() -> list[Tool]:
    """List available SQL Server tools."""
    command = get_command()
    logger.info("Listing tools...")
    return [
        Tool(
            name=command,
            description="Execute an SQL query on the SQL Server",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The SQL query to execute"
                    }
                },
                "required": ["query"]
            }
        ),
        Tool(
            name="execute_sql_file",
            description="Execute SQL statements from a file. The file must be located in an allowed directory (/workspace/sql, ./sql, or sql) and have a .sql extension. Supports multiple statements separated by semicolons or GO batches.",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {
                        "type": "string",
                        "description": "Path to the SQL file to execute (must be in allowed directories: /workspace/sql, ./sql, or sql)"
                    },
                    "use_transaction": {
                        "type": "boolean",
                        "description": "Whether to execute all statements in a single transaction (default: true). If false, each statement is committed individually.",
                        "default": True
                    }
                },
                "required": ["file_path"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Execute SQL commands."""
    config = get_db_config()
    command = get_command()
    logger.info(f"Calling tool: {name} with arguments: {arguments}")
    
    if name == command:
        query = arguments.get("query")
        if not query:
            raise ValueError("Query is required")
        
        try:
            conn = pymssql.connect(**config)
            cursor = conn.cursor()
            cursor.execute(query)
            
            # Special handling for table listing
            if is_select_query(query) and "INFORMATION_SCHEMA.TABLES" in query.upper():
                tables = cursor.fetchall()
                result = ["Tables_in_" + config["database"]]  # Header
                result.extend([table[0] for table in tables])
                cursor.close()
                conn.close()
                return [TextContent(type="text", text="\n".join(result))]
            
            # Regular SELECT queries
            elif is_select_query(query):
                columns = [desc[0] for desc in cursor.description]
                rows = cursor.fetchall()
                result = [",".join(map(str, row)) for row in rows]
                cursor.close()
                conn.close()
                return [TextContent(type="text", text="\n".join([",".join(columns)] + result))]
            
            # Non-SELECT queries
            else:
                conn.commit()
                affected_rows = cursor.rowcount
                cursor.close()
                conn.close()
                return [TextContent(type="text", text=f"Query executed successfully. Rows affected: {affected_rows}")]
                    
        except Exception as e:
            logger.error(f"Error executing SQL '{query}': {e}")
            return [TextContent(type="text", text=f"Error executing query: {str(e)}")]
    
    elif name == "execute_sql_file":
        file_path = arguments.get("file_path")
        if not file_path:
            raise ValueError("file_path is required")
        
        use_transaction = arguments.get("use_transaction", True)
        
        try:
            # Validate file path for security
            validated_path = validate_sql_file_path(file_path)
            logger.info(f"Validated SQL file path: {validated_path}")
            
            # Read file content
            with open(validated_path, 'r', encoding='utf-8') as f:
                sql_content = f.read()
            
            logger.info(f"Read SQL file: {validated_path} ({len(sql_content)} bytes)")
            
            # Split into individual statements
            statements = split_sql_statements(sql_content)
            logger.info(f"Found {len(statements)} SQL statements")
            
            if not statements:
                return [TextContent(type="text", text="No SQL statements found in file")]
            
            # Execute statements
            conn = pymssql.connect(**config)
            cursor = conn.cursor()
            
            results = []
            total_affected = 0
            successful_count = 0
            failed_count = 0
            
            if use_transaction:
                # Execute all statements in a single transaction
                try:
                    for i, stmt in enumerate(statements):
                        if not stmt.strip():
                            continue
                        
                        logger.info(f"Executing statement {i+1}/{len(statements)}")
                        cursor.execute(stmt)
                        
                        # Check if it's a SELECT query
                        if is_select_query(stmt):
                            columns = [desc[0] for desc in cursor.description]
                            rows = cursor.fetchall()
                            result_text = f"Statement {i+1} (SELECT): {len(rows)} rows returned\n"
                            result_text += ",".join(columns) + "\n"
                            result_text += "\n".join([",".join(map(str, row)) for row in rows[:100]])  # Limit output
                            if len(rows) > 100:
                                result_text += f"\n... and {len(rows) - 100} more rows"
                            results.append(result_text)
                        else:
                            affected = cursor.rowcount
                            total_affected += affected if affected >= 0 else 0
                            successful_count += 1
                    
                    # Commit the transaction
                    conn.commit()
                    logger.info(f"Transaction committed successfully")
                    
                    cursor.close()
                    conn.close()
                    
                    summary = f"\n\n=== Execution Summary ===\n"
                    summary += f"Total statements: {len(statements)}\n"
                    summary += f"Successful: {successful_count}\n"
                    summary += f"Total rows affected: {total_affected}\n"
                    summary += f"Transaction: committed\n"
                    
                    return [TextContent(type="text", text="\n\n".join(results) + summary)]
                    
                except Exception as e:
                    # Rollback on error
                    conn.rollback()
                    logger.error(f"Transaction rolled back due to error: {e}")
                    cursor.close()
                    conn.close()
                    return [TextContent(type="text", text=f"Error executing SQL file (transaction rolled back): {str(e)}")]
            
            else:
                # Execute each statement individually with auto-commit
                for i, stmt in enumerate(statements):
                    if not stmt.strip():
                        continue
                    
                    try:
                        logger.info(f"Executing statement {i+1}/{len(statements)}")
                        cursor.execute(stmt)
                        
                        # Check if it's a SELECT query
                        if is_select_query(stmt):
                            columns = [desc[0] for desc in cursor.description]
                            rows = cursor.fetchall()
                            result_text = f"Statement {i+1} (SELECT): {len(rows)} rows returned\n"
                            result_text += ",".join(columns) + "\n"
                            result_text += "\n".join([",".join(map(str, row)) for row in rows[:100]])  # Limit output
                            if len(rows) > 100:
                                result_text += f"\n... and {len(rows) - 100} more rows"
                            results.append(result_text)
                        else:
                            conn.commit()
                            affected = cursor.rowcount
                            total_affected += affected if affected >= 0 else 0
                            successful_count += 1
                            results.append(f"Statement {i+1}: {affected if affected >= 0 else 'N/A'} rows affected")
                    
                    except Exception as e:
                        failed_count += 1
                        results.append(f"Statement {i+1} FAILED: {str(e)}")
                        logger.error(f"Statement {i+1} failed: {e}")
                
                cursor.close()
                conn.close()
                
                summary = f"\n\n=== Execution Summary ===\n"
                summary += f"Total statements: {len(statements)}\n"
                summary += f"Successful: {successful_count}\n"
                summary += f"Failed: {failed_count}\n"
                summary += f"Total rows affected: {total_affected}\n"
                summary += f"Transaction mode: individual commits\n"
                
                return [TextContent(type="text", text="\n\n".join(results) + summary)]
                    
        except ValueError as e:
            # Security validation errors
            logger.error(f"Security validation failed: {e}")
            return [TextContent(type="text", text=f"Security error: {str(e)}")]
        except FileNotFoundError as e:
            logger.error(f"File not found: {e}")
            return [TextContent(type="text", text=f"File not found: {str(e)}")]
        except Exception as e:
            logger.error(f"Error executing SQL file '{file_path}': {e}", exc_info=True)
            return [TextContent(type="text", text=f"Error executing SQL file: {str(e)}")]
    
    else:
        raise ValueError(f"Unknown tool: {name}")

async def main():
    """Main entry point to run the MCP server."""
    from mcp.server.stdio import stdio_server
    
    logger.info("Starting MSSQL MCP server...")
    config = get_db_config()
    # Log connection info without exposing sensitive data
    server_info = config['server']
    if 'port' in config:
        server_info += f":{config['port']}"
    user_info = config.get('user', 'Windows Auth')
    logger.info(f"Database config: {server_info}/{config['database']} as {user_info}")
    
    async with stdio_server() as (read_stream, write_stream):
        try:
            await app.run(
                read_stream,
                write_stream,
                app.create_initialization_options()
            )
        except Exception as e:
            logger.error(f"Server error: {str(e)}", exc_info=True)
            raise

if __name__ == "__main__":
    asyncio.run(main())
