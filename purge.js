require('dotenv').config();
const { Pool } = require('pg');

(async () => {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });
  try {
    const res = await pool.query(`
      DELETE
        FROM attachments
       WHERE casenum NOT IN (SELECT casenum FROM cases);
    `);
    console.log('Deleted', res.rowCount, 'orphaned attachments');
  } catch (err) {
    console.error('Error purging attachments:', err);
  } finally {
    await pool.end();
  }
})();
