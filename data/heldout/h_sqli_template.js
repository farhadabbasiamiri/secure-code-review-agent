const { Pool } = require("pg");
const pool = new Pool();

async function findOrders(req, res) {
  const status = req.query.status;
  const result = await pool.query(`SELECT id, total FROM orders WHERE status = '${status}'`);
  res.json(result.rows);
}

module.exports = { findOrders };
