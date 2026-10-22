# amazing-byte-bakery

Contact page: the navbar opens `/contact`; contact submissions are stored in `contact_messages`. `flask init-db` creates this table if missing.

Paytm: real Paytm payments are not enabled in this package because Paytm Merchant credentials and callback/signature configuration are required. Do not treat a mock button as a real payment. Keep credentials only in Render environment variables.
