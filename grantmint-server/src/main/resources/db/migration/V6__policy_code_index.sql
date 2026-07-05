-- The webhook policy-map resolver looks policies up by code alone
-- (PolicyRepository.findByCode); the only index carrying code is the composite
-- uq_policies_product_code UNIQUE(product_id, code), whose leading column is
-- product_id — a code-only lookup cannot use it and falls back to a sequential
-- scan on every webhook event. A plain B-tree on code keeps that resolver
-- index-served as webhook volume grows. Non-unique on purpose: the same code
-- may legitimately exist under different products.
CREATE INDEX ix_policies_code ON policies (code);
