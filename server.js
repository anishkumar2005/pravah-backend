// PRAVAAH BACKEND SERVER
// Receives sensor readings, stores them, calculates risk, serves data to dashboards

const express = require('express');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// ---------- IN-MEMORY STORAGE (simple for demo) ----------
let readings = {}; // keyed by node_id, stores latest + history

// ---------- ROUTE 1: Receive a reading from the sensor ----------
app.post('/api/readings', (req, res) => {
  const data = req.body;

  if (!data.node_id || data.water_level_cm === undefined) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const riskScore = calculateRisk(data.percent_full, data.rate_of_rise_cm_per_min);

  const record = {
    ...data,
    risk_score: riskScore,
    risk_level: getRiskLevel(riskScore),
    timestamp: new Date().toISOString()
  };

  if (!readings[data.node_id]) {
    readings[data.node_id] = { history: [] };
  }
  readings[data.node_id].latest = record;
  readings[data.node_id].history.push(record);
  if (readings[data.node_id].history.length > 500) {
    readings[data.node_id].history.shift();
  }

  console.log("Received:", record);
  res.status(200).json({ message: "Reading saved", risk_level: record.risk_level });
});

// ---------- ROUTE 2: Latest reading for every node (citizen map + dashboard) ----------
app.get('/api/nodes', (req, res) => {
  const nodeList = Object.keys(readings).map(id => ({
    node_id: id,
    ...readings[id].latest
  }));
  res.json(nodeList);
});

// ---------- ROUTE 3: History for one node (graphs) ----------
app.get('/api/nodes/:id/history', (req, res) => {
  const node = readings[req.params.id];
  if (!node) return res.status(404).json({ error: "Node not found" });
  res.json(node.history);
});

// ---------- ROUTE 4: Mark a node as cleaned (municipal dashboard) ----------
app.post('/api/nodes/:id/clean', (req, res) => {
  const node = readings[req.params.id];
  if (!node) return res.status(404).json({ error: "Node not found" });

  node.latest.risk_score = 0;
  node.latest.risk_level = "safe";
  node.latest.last_cleaned = new Date().toISOString();

  res.json({ message: "Marked as cleaned", node: node.latest });
});

// ---------- ROUTE 5: Health check ----------
app.get('/', (req, res) => {
  res.send("Pravaah backend is running.");
});

// ---------- RISK LOGIC ----------
function calculateRisk(percentFull, rateOfRise) {
  let score = percentFull;
  if (rateOfRise > 2) score += 20;
  else if (rateOfRise > 0.5) score += 10;
  return Math.min(Math.round(score), 100);
}

function getRiskLevel(score) {
  if (score > 70) return "critical";
  if (score > 40) return "watch";
  return "safe";
}

// Render provides PORT automatically
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
