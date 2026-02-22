const express = require('express');
const pm2 = require('pm2');
const cors = require('cors');
const path = require('path');
const { exec } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3434;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Connect to PM2
pm2.connect((err) => {
    if (err) {
        console.error(err);
        process.exit(2);
    }
});

// API Routes
app.get('/api/list', (req, res) => {
    pm2.list((err, list) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(list.map(p => ({
            id: p.pm_id,
            name: p.name,
            status: p.pm2_env.status,
            cpu: p.monit.cpu,
            memory: p.monit.memory,
            uptime: p.pm2_env.pm_uptime,
            restarts: p.pm2_env.restart_time,
            out: p.pm2_env.pm_out_log_path,
            err: p.pm2_env.pm_err_log_path
        })));
    });
});

app.get('/api/logs/:id', (req, res) => {
    const id = req.params.id;
    const type = req.query.type || 'out'; // 'out' or 'err'
    const limit = parseInt(req.query.limit) || 500;

    pm2.describe(id, (err, list) => {
        if (err || list.length === 0) return res.status(500).json({ error: 'Process not found' });
        
        const logPath = type === 'err' ? list[0].pm2_env.pm_err_log_path : list[0].pm2_env.pm_out_log_path;
        
        exec(`tail -n ${limit} ${logPath}`, (err, stdout) => {
            if (err) return res.status(500).json({ error: 'Failed to read logs' });
            res.json({ logs: stdout, type, limit });
        });
    });
});

app.post('/api/restart/:id', (req, res) => {
    const id = req.params.id;
    pm2.restart(id, (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, message: `Process ${id} restarted` });
    });
});

app.post('/api/stop/:id', (req, res) => {
    const id = req.params.id;
    pm2.stop(id, (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, message: `Process ${id} stopped` });
    });
});

app.post('/api/start/:id', (req, res) => {
    const id = req.params.id;
    pm2.start(id, (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, message: `Process ${id} started` });
    });
});

// Start a new script
app.post('/api/add', (req, res) => {
    const { script, name } = req.body;
    if (!script) return res.status(400).json({ error: 'Script path is required' });

    pm2.start({
        script: script,
        name: name || path.basename(script)
    }, (err, apps) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true, message: 'Process started', app: apps[0] });
    });
});

app.listen(PORT, () => {
    console.log(`PM2 Web Manager running on http://localhost:${PORT}`);
});
