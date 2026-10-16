-- VeriGuard capstone schema (Azure SQL / SQLite compatible)
CREATE TABLE branches (branch_code VARCHAR(10) PRIMARY KEY, branch_name VARCHAR(80), city VARCHAR(60), state VARCHAR(60));
CREATE TABLE customers_kyc (customer_id VARCHAR(20) PRIMARY KEY, full_name VARCHAR(120), customer_type VARCHAR(20), segment VARCHAR(20),
  date_of_birth DATE, nationality VARCHAR(40), occupation VARCHAR(120), annual_income_declared_inr DECIMAL(18,2),
  expected_monthly_volume_inr DECIMAL(18,2), risk_category VARCHAR(10), pep_flag CHAR(1), aadhaar_number VARCHAR(20), pan VARCHAR(12),
  phone VARCHAR(20), email VARCHAR(120), address VARCHAR(250), state VARCHAR(60), home_branch VARCHAR(10), onboarding_date DATE,
  kyc_last_updated DATE, documents_on_file VARCHAR(400));
CREATE TABLE accounts (account_id VARCHAR(20) PRIMARY KEY, account_number VARCHAR(20), customer_id VARCHAR(20) REFERENCES customers_kyc(customer_id),
  account_type VARCHAR(10), branch_code VARCHAR(10), open_date DATE, status VARCHAR(40), last_contact_change_date DATE);
CREATE TABLE transactions (txn_id VARCHAR(20) PRIMARY KEY, account_id VARCHAR(20) REFERENCES accounts(account_id), customer_id VARCHAR(20),
  txn_timestamp DATETIME, channel VARCHAR(20), direction CHAR(2), amount_inr DECIMAL(18,2), branch_code VARCHAR(10),
  counterparty_name VARCHAR(120), counterparty_account VARCHAR(30), counterparty_bank VARCHAR(80), counterparty_country VARCHAR(5), narration VARCHAR(200));
CREATE TABLE watchlist (entity_id VARCHAR(20) PRIMARY KEY, name VARCHAR(120), aliases VARCHAR(250), date_of_birth DATE, nationality VARCHAR(40),
  list_type VARCHAR(20), designation_detail VARCHAR(250), id_document VARCHAR(40), listed_on DATE);
CREATE TABLE adverse_media (entity_name VARCHAR(120), headline VARCHAR(250), source VARCHAR(120), published DATE, summary VARCHAR(500));
CREATE TABLE high_risk_jurisdictions (code VARCHAR(5) PRIMARY KEY, name VARCHAR(80), category VARCHAR(30));
CREATE TABLE alerts (alert_id VARCHAR(20) PRIMARY KEY, customer_id VARCHAR(20), account_id VARCHAR(20), rule_id VARCHAR(5), rule_description VARCHAR(250),
  triggered_at DATETIME, priority VARCHAR(10), status VARCHAR(30));
CREATE INDEX ix_txn_cust ON transactions(customer_id, txn_timestamp);
CREATE INDEX ix_txn_acct ON transactions(account_id, txn_timestamp);
