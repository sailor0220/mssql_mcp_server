import asyncio
import logging
import os
import re
import pathlib
import uuid
import random
import string
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
        ),
        Tool(
            name="get_po_execution_summary",
            description="Execute a complex PO (Purchase Order) execution summary report query. Creates a temporary table with PO data including delivery,入库，开票，and payment status. Returns comprehensive PO details with custom fields.",
            inputSchema={
                "type": "object",
                "properties": {
                    "start_date": {
                        "type": "string",
                        "description": "Start date for filtering PO records (format: YYYY-MM-DD)"
                    },
                    "end_date": {
                        "type": "string",
                        "description": "End date for filtering PO records (format: YYYY-MM-DD)"
                    }
                },
                "required": ["start_date", "end_date"]
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
    
    elif name == "get_po_execution_summary":
        start_date = arguments.get("start_date")
        end_date = arguments.get("end_date")
        
        if not start_date or not end_date:
            raise ValueError("start_date and end_date are required")
        
        try:
            conn = pymssql.connect(**config)
            cursor = conn.cursor()
            
            # Generate table name: uftemp_uuid_random6
            unique_id = str(uuid.uuid4()).replace('-', '')[:8]
            random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
            table_name = f"uftemp_{unique_id}_{random_suffix}"
            
            logger.info(f"Generated temp table name: {table_name}")
            
            # Build the complex PO execution summary query
            sql = f"""
DECLARE @start_date varchar(50);
DECLARE @end_date varchar(50);
DECLARE @table_name varchar(50);

SET @start_date = '{start_date}';
SET @end_date = '{end_date}';
SET @table_name = '{table_name}';

DECLARE @sql NVARCHAR(MAX);
SET @sql = N'
WITH PO AS (
    SELECT PO_Podetails.ID,
        (CASE WHEN ISNULL(Inventory.binvtype,0)=0 AND ISNULL(Inventory.bservice,0)=0 AND Po_PoMain.cbustype<>''直运采购'' 
         THEN (CASE WHEN (ISNULL(PO_Podetails.ireceivedqty,0)+ISNULL(PO_Podetails.freceivedqty,0)) >= ISNULL(PO_Podetails.iquantity,0) AND ISNULL(PO_Podetails.iquantity,0) > 0 
              THEN ''到货完成'' 
              ELSE (CASE WHEN ISNULL(PO_Podetails.iarrqty,0) >= ISNULL(PO_Podetails.iquantity,0) AND ISNULL(PO_Podetails.iquantity,0) > 0 THEN ''到货完成'' ELSE ''到货未完成'' END) 
         END) 
         ELSE NULL END) AS e1code, 
        (CASE WHEN ISNULL(Inventory.binvtype,0)=0 AND ISNULL(Inventory.bservice,0)=0 AND Po_PoMain.cbustype<>''直运采购'' 
         THEN (CASE WHEN (ISNULL(PO_Podetails.ireceivedqty,0)+ISNULL(PO_Podetails.freceivedqty,0)) >= ISNULL(PO_Podetails.iquantity,0) AND ISNULL(PO_Podetails.iquantity,0) > 0 THEN ''入库完成'' ELSE ''入库未完成'' END) 
         ELSE NULL END) AS e2code,
        (CASE WHEN Po_PoMain.cbustype =''代管采购'' THEN NULL 
         ELSE (CASE WHEN ISNULL(PO_Podetails.iinvqty,0) >= ISNULL(PO_Podetails.iquantity,0) AND ISNULL(PO_Podetails.iquantity,0) > 0 THEN ''开票完成'' ELSE ''开票未完成'' END) 
         END) AS e3code,
        (CASE WHEN Po_PoMain.cbustype =''代管采购'' THEN NULL 
         ELSE (CASE WHEN ISNULL(iUnitPrice,0) > 0 THEN (CASE WHEN ISNULL(ioritotal,0) >= ISNULL(isum,0) OR (ISNULL(purTbls.fpQuantity,0)>=PO_Podetails.iQuantity AND ISNULL(purTbls.fpOriTotal,0)>= ISNULL(purTbls.fOriSum,0)) THEN ''付款完成'' ELSE ''付款未完成'' END) 
              ELSE (CASE WHEN (ISNULL(purTbls.fpQuantity,0)>=PO_Podetails.iQuantity AND ISNULL(purTbls.fpOriTotal,0)>= ISNULL(purTbls.fOriSum,0)) THEN ''付款完成'' ELSE ''付款未完成'' END) 
         END) END) AS e4code, 
        (CASE WHEN ISNULL(Po_PoDetails.sotype,'''') = '''' THEN 0 ELSE Po_PoDetails.sotype END) AS e5code  
    FROM PO_Pomain WITH (NOLOCK) 
    JOIN PO_Podetails WITH (NOLOCK) ON PO_Pomain.POID = PO_Podetails.POID  
    LEFT JOIN (SELECT PurBillVouchs.iPOsID, SUM(ISNULL(iPBVQuantity,0)) AS fpQuantity, SUM(ISNULL(iOriTotal,0)) AS fpOriTotal, SUM(ISNULL(iOriSum,0)) AS fOriSum 
               FROM PurBillVouch WITH (NOLOCK) INNER JOIN PurBillVouchs WITH (NOLOCK) ON PurBillVouch.PBVID=PurBillVouchs.PBVID 
               WHERE cBusType <> N''委外加工'' GROUP BY PurBillVouchs.iPOsID) AS purTbls ON purTbls.iPosID=PO_Podetails.ID  
    LEFT JOIN Inventory WITH (NOLOCK) ON Po_PoDetails.cInvCode = Inventory.cInvCode  
    WHERE ISNULL(PO_POmain.cVerifier,'''')<>'''' 
      AND PO_POmain.dPODate >= @start_date 
      AND PO_POmain.dPODate <= @end_date 
),
arrTmp AS (
    SELECT iposid, SUM(ISNULL(iquantity,0)) AS fqty, SUM(ISNULL(inum,0)) AS fnum 
    FROM PO 
    LEFT JOIN pu_arrivalvouchs WITH (NOLOCK) ON po.id=pu_arrivalvouchs.iposid 
    LEFT JOIN pu_arrivalvouch WITH (NOLOCK) ON pu_arrivalvouch.id=pu_arrivalvouchs.id 
    WHERE iBillType = 2 AND ISNULL(iposid,0)<>0 AND cbustype<>N''委外加工''  
    GROUP BY iposid
),
a AS (
    SELECT PO_Podetails.ID,
        (CASE WHEN ISNULL(Inventory.binvtype,0)=0 AND ISNULL(Inventory.bservice,0)=0 AND Po_PoMain.cbustype<>''直运采购'' 
         THEN (CASE WHEN (ISNULL(PO_Podetails.ireceivedqty,0)+ISNULL(PO_Podetails.freceivedqty,0)) >= ISNULL(PO_Podetails.iquantity,0) AND ISNULL(PO_Podetails.iquantity,0) > 0 
              THEN ''到货完成'' 
              ELSE (CASE WHEN ISNULL(PO_Podetails.iarrqty,0) >= ISNULL(PO_Podetails.iquantity,0) AND ISNULL(PO_Podetails.iquantity,0) > 0 THEN ''到货完成'' ELSE ''到货未完成'' END) 
         END) 
         ELSE NULL END) AS e1code, 
        (CASE WHEN ISNULL(Inventory.binvtype,0)=0 AND ISNULL(Inventory.bservice,0)=0 AND Po_PoMain.cbustype<>''直运采购'' 
         THEN (CASE WHEN (ISNULL(PO_Podetails.ireceivedqty,0)+ISNULL(PO_Podetails.freceivedqty,0)) >= ISNULL(PO_Podetails.iquantity,0) AND ISNULL(PO_Podetails.iquantity,0) > 0 THEN ''入库完成'' ELSE ''入库未完成'' END) 
         ELSE NULL END) AS e2code,
        (CASE WHEN Po_PoMain.cbustype =''代管采购'' THEN NULL 
         ELSE (CASE WHEN ISNULL(PO_Podetails.iinvqty,0) >= ISNULL(PO_Podetails.iquantity,0) AND ISNULL(PO_Podetails.iquantity,0) > 0 THEN ''开票完成'' ELSE ''开票未完成'' END) 
         END) AS e3code,
        (CASE WHEN Po_PoMain.cbustype =''代管采购'' THEN NULL 
         ELSE (CASE WHEN ISNULL(iUnitPrice,0) > 0 THEN (CASE WHEN ISNULL(ioritotal,0) >= ISNULL(isum,0) OR (ISNULL(purTbls.fpQuantity,0)>=PO_Podetails.iQuantity AND ISNULL(purTbls.fpOriTotal,0)>= ISNULL(purTbls.fOriSum,0)) THEN ''付款完成'' ELSE ''付款未完成'' END) 
              ELSE (CASE WHEN (ISNULL(purTbls.fpQuantity,0)>=PO_Podetails.iQuantity AND ISNULL(purTbls.fpOriTotal,0)>= ISNULL(purTbls.fOriSum,0)) THEN ''付款完成'' ELSE ''付款未完成'' END) 
         END) END) AS e4code, 
        (CASE WHEN ISNULL(Po_PoDetails.sotype,'''') = '''' THEN 0 ELSE Po_PoDetails.sotype END) AS e5code  
    FROM PO_Pomain WITH (NOLOCK) 
    JOIN PO_Podetails WITH (NOLOCK) ON PO_Pomain.POID = PO_Podetails.POID  
    LEFT JOIN (SELECT PurBillVouchs.iPOsID, SUM(ISNULL(iPBVQuantity,0)) AS fpQuantity, SUM(ISNULL(iOriTotal,0)) AS fpOriTotal, SUM(ISNULL(iOriSum,0)) AS fOriSum 
               FROM PurBillVouch WITH (NOLOCK) INNER JOIN PurBillVouchs WITH (NOLOCK) ON PurBillVouch.PBVID=PurBillVouchs.PBVID 
               WHERE cBusType <> N''委外加工'' GROUP BY PurBillVouchs.iPOsID) AS purTbls ON purTbls.iPosID=PO_Podetails.ID  
    LEFT JOIN Inventory WITH (NOLOCK) ON Po_PoDetails.cInvCode = Inventory.cInvCode  
    WHERE ISNULL(PO_POmain.cVerifier,'''')<>'''' 
      AND PO_POmain.dPODate >= @start_date 
      AND PO_POmain.dPODate <= @end_date 
),
PoTmp AS (
    SELECT iPosid, SUM(iPrice) AS iPrice, SUM(iorimoney) AS RDiorimoney, SUM(iSum) AS RDiSum 
    FROM pu_rdrecords WITH(NOLOCK) JOIN PO ON pu_rdrecords.iPosid=po.ID  
    WHERE NOT iPosid IS NULL  
    GROUP BY iPosid
)
SELECT
    CONVERT(NVARCHAR(30),PO_POdetails.ID) AS ID,
    CONVERT(NVARCHAR(30),Po_PoMain.POID) AS POID,
    CONVERT(NVARCHAR(30),Po_PoMain.cPOID) AS 订单号，
    Po_PoMain.cVenCode AS 供应商编码，
    Vendor.cVenAbbName AS 供应商简称，
    Inventory.cInvCode AS 存货编码，
    Inventory.cInvName AS 存货名称，
    Inventory.cInvAddCode AS 存货代码，
    Inventory.cInvStd AS 规格型号，
    CASE WHEN ISNULL(Inventory.bService,0)=0 THEN ''否'' ELSE ''是'' END 是否应税劳务，
    Unit1.cComUnitName as 主计量，
    Po_PoDetails.iQuantity as 数量，
    CASE WHEN ISNULL(inventory.iGroupType,0)=0 THEN NULL ELSE Unit2.cComUnitName END as 辅计量，
    (CASE WHEN CONVERT(DECIMAL(20,7),ISNULL(Po_PoDetails.iNum,0))=CONVERT(DECIMAL(20,7),0) THEN NULL 
          ELSE (CASE WHEN Inventory.iGroupType=1 THEN Unit2.iChangRate ELSE Po_PoDetails.iQuantity/Po_PoDetails.iNum END) 
     END) AS 换算率，
    Po_Podetails.cItem_class 项目大类编码，
    fitem.cItem_Name 项目大类名称，
    Po_Podetails.cItemName 项目名称，
    Po_Podetails.cItemCode 项目编码，
    Po_PoDetails.iNum 辅计量数量，
    Po_PoDetails.iMoney 原币无税金额，
    Po_PoDetails.iNatMoney 本币无税金额，
    Po_PoDetails.iNatSum as 本币价税合计，
    Po_Podetails.iSum as 原币价税合计，
    (ISNULL(Po_PoDetails.ireceivedqty,0)+ISNULL(Po_PoDetails.freceivedqty,0)) AS 累计到货数量，
    (CASE WHEN ISNULL(inventory.igrouptype,0)=1 THEN (ISNULL(Po_PoDetails.iReceivedQTY,0)+ISNULL(Po_PoDetails.fReceivedQTY,0))/unit2.ichangrate 
          ELSE (ISNULL(Po_PoDetails.iReceivedNum,0)+ISNULL(Po_PoDetails.fReceivedNum,0)) 
     END) as 累计入库件数，
    (ISNULL(PoTmp.iPrice,0)) AS 累计入库金额，
    (ISNULL(PoTmp.RDiorimoney,0)) as RDiorimoney,
    (ISNULL(PoTmp.RDiSum,0)) as RDiSum,
    Po_PoDetails.iInvQTY AS 累计发票数量，
    (CASE WHEN ISNULL(inventory.igrouptype,0)=1 THEN (ISNULL(Po_PoDetails.iInvQTY,0))/unit2.ichangrate ELSE Po_PoDetails.iInvNUM END) AS 累计发票件数，
    Po_PoDetails.iNatInvMoney AS 发票本币价税合计，
    Po_PoDetails.iInvMoney AS 发票原币价税合计，
    Po_PoDetails.iTotal AS sumT, Po_PoDetails.iOriTotal AS 原币累计付款，
    (CASE WHEN ISNULL(inventory.igrouptype,0)=1 THEN iarrqty/unit2.ichangrate ELSE po_podetails.iarrnum END) as 净到货件数，
    Po_PoDetails.iArrMoney 原币到货金额，
    Po_PoDetails.iNatArrMoney 本币到货金额，
    PO_POdetails.cFree1,PO_POdetails.cFree2,PO_POdetails.cFree3,PO_POdetails.cFree4,PO_POdetails.cFree5,PO_POdetails.cFree6,PO_POdetails.cFree7,PO_POdetails.cFree8,PO_POdetails.cFree9,PO_POdetails.cFree10,
    Po_PoMain.cDefine1 ,Po_PoMain.cDefine2, Po_PoMain.cDefine3 ,Po_PoMain.cDefine4 ,Po_PoMain.cDefine5 ,Po_PoMain.cDefine6 ,Po_PoMain.cDefine7 ,Po_PoMain.cDefine8 ,Po_PoMain.cDefine9 , Po_PoMain.cDefine10 ,
    Po_PoMain.cDefine11 ,Po_PoMain.cDefine12 ,Po_PoMain.cDefine13 ,Po_PoMain.cDefine14 ,Po_PoMain.cDefine15 ,Po_PoMain.cDefine16 ,
    PO_POdetails.cDefine22 ,PO_POdetails.cDefine23 ,PO_POdetails.cDefine24 , PO_POdetails.cDefine25 ,PO_POdetails.cDefine26 ,PO_POdetails.cDefine27 ,PO_POdetails.cDefine28 ,PO_POdetails.cDefine29 ,PO_POdetails.cDefine30 ,
    PO_POdetails.cDefine31 ,PO_POdetails.cDefine32 , PO_POdetails.cDefine33 ,PO_POdetails.cDefine34 ,PO_POdetails.cDefine35 ,PO_POdetails.cDefine36 ,PO_POdetails.cDefine37 ,
    Inventory.[cinvDefine1],Inventory.[cinvDefine2],Inventory.[cinvDefine3], Inventory.[cinvDefine4],Inventory.[cinvDefine5],Inventory.[cinvDefine6],Inventory.[cinvDefine7],Inventory.[cinvDefine8],Inventory.[cinvDefine9],Inventory.[cinvDefine10],Inventory.[cinvDefine11], 
    Inventory.[cinvDefine12],Inventory.[cinvDefine13],Inventory.[cinvDefine14],Inventory.[cinvDefine15],Inventory.[cinvDefine16],
    [cVenDefine1],[cVenDefine2],[cVenDefine3],[cVenDefine4],[cVenDefine5],[cVenDefine6],[cVenDefine7],[cVenDefine8],[cVenDefine9],[cVenDefine10],  [cVenDefine11],[cVenDefine12],[cVenDefine13],[cVenDefine14],[cVenDefine15],[cVenDefine16],
    ISNULL(po_podetails.fPoValidQuantity,0) as 合格数量，
    (CASE WHEN Ap_Order.ID<>0 THEN Ap_Order.iAmount ELSE Ap_Order1.iAmount END) AS 预付款本币，
    (CASE WHEN Ap_Order.ID<>0 THEN Ap_Order.iAmount_f ELSE Ap_Order1.iAmount_f END) AS 预付款原币，
    (CASE WHEN Ap_Order.ID<>0 THEN Ap_Order.iRAmount ELSE Ap_Order1.iRAmount END) AS 预付款核销余额本币，
    (CASE WHEN Ap_Order.ID<>0 THEN Ap_Order.iRAmount_f ELSE Ap_Order1.iRAmount_f END) AS 预付款核销余额原币，
    ISNULL(PO_POdetails.fPoArrQuantity,0) as 到货数量，
    (ISNULL(Po_PoDetails.fPoRetQuantity,0)) as 退货数量，
    ABS(ISNULL(arrtmp.fqty,0)) as 拒收数量，
    ABS(ISNULL(arrtmp.fnum,0)) as 拒收件数，
    ISNULL(Customer.cCusCode,'''') as 客户编码，
    ISNULL(Customer.cCusAbbName,'''') as 客户简称，
    ISNULL(po_podetails.ContractCode,'''') AS 合同号，
    ISNULL(po_podetails.ContractRowNo,'''') AS 合同标的编码，
    po_podetails.irowno 需求跟踪行号，Po_PoMain.cexch_name as 币种，
    (CASE WHEN po_podetails.sotype=4 THEN cRClassName END) as 需求分类代号说明，
    cBusTypeView.EnumName AS 业务类型，
    po_podetails.csocode 需求跟踪号，
    po_podetails.darrivedate 计划到货日期，
    PO_POmain.dPODate as 日期，
    PO_POmain.cMemo as 备注，
    Department.cDepName as 部门，
    PO_POmain.cMaker as 制单人，
    Po_PoDetails.cbCloser as 关闭人，
    Person.cPersonName as 业务员，PO_POmain.cVerifier as 审核人，
    (CASE Po_Podetails.cSource WHEN ''app'' THEN Po_Podetails.cupsocode ELSE '''' END) as 请购单号，
    Po_Podetails.fexquantity as 累计出口数量，
    PO_POmain.cChangVerifier 变更审批人，
    PO_POmain.cptcode as 采购类型编码，
    PurchaseType.cptname as 采购类型，
    po_podetails.planlotnumber as 批次号，
    Po_PoDetails.cfactorycode ,
    factory.cfactoryname ,
    e5.EnumName as sotype,
    e1.EnumName as 到货状态，
    e2.EnumName as 入库状态，
    e3.EnumName as 开票状态，
    e4.EnumName as 付款状态
INTO tempdb..' + QUOTENAME(@table_name) + N'
FROM Po_PoDetails WITH(NOLOCK)  
LEFT JOIN Inventory WITH (NOLOCK) ON Po_PoDetails.cInvCode = Inventory.cInvCode  
LEFT JOIN Po_PoMain WITH (NOLOCK) ON Po_PoMain.POID = Po_PoDetails.POID  
LEFT JOIN a ON a.id=po_podetails.id 
LEFT JOIN Vendor WITH (NOLOCK) ON Po_PoMain.cVenCode=Vendor.cVenCode  
LEFT JOIN ComputationUnit as Unit1 ON inventory.cComUnitCode=Unit1.cComUnitCode  
LEFT JOIN ComputationUnit as Unit2 ON po_podetails.cUnitId=Unit2.cComUnitCode  
LEFT JOIN fitem ON Po_Podetails.cItem_class=fitem.cItem_class  
LEFT JOIN PoTmp ON PoTmp.iPosid=Po_Podetails.ID 
LEFT JOIN arrTmp ON arrTmp.iPosid=Po_Podetails.ID 
LEFT JOIN Ap_OrderPU Ap_Order ON Ap_Order.ID=Po_PoDetails.ID AND Ap_Order.ID<>0 AND (Ap_Order.cFlag=N''AP'') AND Ap_Order.iordertype = 0 
LEFT JOIN Ap_OrderPU Ap_Order1 ON Ap_Order1.cOrderID=Po_PoMain.cPoid AND Ap_Order1.ID=0 AND (Ap_Order1.cFlag=N''AP'') AND Ap_Order1.iordertype = 0 
LEFT JOIN AA_RequirementClass ON AA_RequirementClass.cRClassCode=po_podetails.sodid AND po_podetails.sotype =4 
LEFT JOIN (SELECT csocode,1 AS isotype,ccuscode FROM so_somain UNION SELECT ccode AS csocode,3 AS isotype,ccuscode FROM ex_order) so_somain ON so_somain.csocode=po_podetails.csoordercode AND po_podetails.iordertype=so_somain.isotype  
LEFT JOIN Customer WITH (NOLOCK) ON SO_SOMain.cCusCode=Customer.cCusCode 
LEFT JOIN AA_Enum AS cBusTypeView ON cBusTypeView.EnumType=N''PU.BusType'' AND cBusTypeView.EnumCode =Po_Pomain.cBusType AND cBusTypeView.LocaleID=N''zh-CN''  
LEFT JOIN Department WITH (NOLOCK) ON Po_PoMain.cDepCode=Department.cDepCode 
LEFT JOIN Person WITH (NOLOCK) ON Po_PoMain.cPersonCode=Person.cPersonCode  
LEFT JOIN PurchaseType WITH (NOLOCK) ON Po_PoMain.cptcode=PurchaseType.cptcode  
LEFT JOIN factory WITH (NOLOCK) ON factory.cfactorycode=Po_PoDetails.cfactorycode   
LEFT JOIN aa_enum e1 ON a.e1code=e1.EnumCode AND e1.EnumType=''PU.Report.AdvanceCondic'' AND e1.LocaleID=N''zh-CN''  
LEFT JOIN aa_enum e2 ON a.e2code=e2.EnumCode AND e2.EnumType=''PU.Report.AdvanceCondic'' AND e2.LocaleID=N''zh-CN''  
LEFT JOIN aa_enum e3 ON a.e3code=e3.EnumCode AND e3.EnumType=''PU.Report.AdvanceCondic'' AND e3.LocaleID=N''zh-CN''  
LEFT JOIN aa_enum e4 ON a.e4code=e4.EnumCode AND e4.EnumType=''PU.Report.AdvanceCondic'' AND e4.LocaleID=N''zh-CN'' 
LEFT JOIN aa_enum e5 ON a.e5code= e5.EnumCode AND e5.EnumType = ''EnumSoType'' AND e5.LocaleID=N''zh-CN'' 
WHERE (1 = 1) 
  AND ((ISNULL(PO_POmain.cVerifier, '''') <> '''') OR (ISNULL(PO_POmain.cChangVerifier, '''') <> '''')) 
  AND (PO_POmain.dPODate >= @start_date) 
  AND (PO_POmain.dPODate <= @end_date) 
  AND ISNULL(Po_podetails.cbCloser, '''') = '''';

SELECT * FROM tempdb..' + QUOTENAME(@table_name) + N';';

SET @sql = @sql + N' IF OBJECT_ID(N''tempdb..' + QUOTENAME(@table_name) + N''') IS NOT NULL DROP TABLE tempdb..' + QUOTENAME(@table_name) + N';';

EXEC sp_executesql @sql,
    N'@start_date varchar(50), @end_date varchar(50)',
    @start_date, @end_date;
"""
            
            logger.info("Executing PO execution summary query")
            cursor.execute(sql)
            
            # Fetch results
            columns = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()
            
            result_text = f"PO Execution Summary ({len(rows)} rows)\n"
            result_text += "=" * 50 + "\n"
            result_text += ",".join(columns) + "\n"
            
            # Return all rows (no limit)
            result_text += "\n".join([",".join(map(str, row)) for row in rows])
            
            cursor.close()
            conn.close()
            
            logger.info(f"Query executed successfully, returned {len(rows)} rows")
            return [TextContent(type="text", text=result_text)]
                
        except Exception as e:
            logger.error(f"Error executing PO execution summary: {e}", exc_info=True)
            return [TextContent(type="text", text=f"Error executing PO execution summary: {str(e)}")]
    
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
