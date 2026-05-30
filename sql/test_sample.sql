-- Test SQL file for execute_sql_file functionality
-- This file demonstrates multiple SQL statements

-- Create a test table
CREATE TABLE test_sql_file (
    id INT IDENTITY(1,1) PRIMARY KEY,
    name NVARCHAR(50),
    created_date DATETIME DEFAULT GETDATE()
);

-- Insert some test data
INSERT INTO test_sql_file (name) VALUES ('Test User 1');
INSERT INTO test_sql_file (name) VALUES ('Test User 2');
INSERT INTO test_sql_file (name) VALUES ('Test User 3');

-- Select to verify data
SELECT * FROM test_sql_file;

-- Update a record
UPDATE test_sql_file SET name = 'Updated User 1' WHERE id = 1;

-- Final select
SELECT * FROM test_sql_file;
