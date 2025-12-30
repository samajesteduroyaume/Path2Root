use crate::types::ScanResponse;

pub fn generate_html_report(scan: &ScanResponse) -> String {
    let json_data = serde_json::to_string(&scan).unwrap_or_default();
    
    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Path2Root Security Report</title>
    <script type="text/javascript" src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 20px; }}
        h1 {{ color: #a5b4fc; border-bottom: 2px solid #6366f1; padding-bottom: 10px; }}
        .metrics {{ display: flex; gap: 20px; margin-bottom: 20px; }}
        .metric-box {{ background: #1e293b; padding: 15px; border-radius: 8px; border: 1px solid #334155; flex: 1; text-align: center; }}
        .metric-value {{ font-size: 24px; font-weight: bold; color: #38bdf8; display: block; }}
        .metric-label {{ font-size: 12px; text-transform: uppercase; color: #94a3b8; }}
        #mynetwork {{ width: 100%; height: 600px; border: 1px solid #334155; background: #020617; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.5); }}
        .section {{ margin-top: 30px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #1e293b; color: #94a3b8; }}
        tr:hover {{ background: #1e293b; }}
        .vuln-high {{ color: #ef4444; font-weight: bold; }}
        .vuln-med {{ color: #f59e0b; }}
        .vuln-low {{ color: #3b82f6; }}
    </style>
</head>
<body>
    <h1>🛡️ Path2Root Security Audit</h1>
    
    <div class="metrics">
        <div class="metric-box">
            <span class="metric-value">{}</span>
            <span class="metric-label">Total Bounty ($)</span>
        </div>
        <div class="metric-box">
            <span class="metric-value">{}</span>
            <span class="metric-label">Critical Paths</span>
        </div>
    </div>

    <div id="mynetwork"></div>

    <div class="section">
        <h2>🔥 Top Vulnerabilities</h2>
        <table>
            <thead><tr><th>Node</th><th>Issue</th><th>Impact</th></tr></thead>
            <tbody>
                <!-- Populated by JS -->
            </tbody>
        </table>
    </div>

    <script>
        const scanData = {};

        // Parse Graph Data
        const nodes = new vis.DataSet(scanData.graph.nodes.map(n => ({{
            id: n.id,
            label: n.label,
            shape: n.node_type === 'Host' ? 'hexagon' : 'dot',
            color: n.id === 'internet' ? '#3b82f6' : (n.properties.status === 'vulnerable' ? '#ef4444' : '#94a3b8'),
            size: n.node_type === 'Host' ? 20 : 10
        }})));
        
        const edges = new vis.DataSet(scanData.graph.edges.map(e => ({{
            from: e.source,
            to: e.target,
            arrows: 'to',
            color: {{ color: '#475569' }}
        }})));

        const container = document.getElementById('mynetwork');
        const data = {{ nodes: nodes, edges: edges }};
        const options = {{
            physics: {{
                stabilization: false,
                barnesHut: {{ gravitationalConstant: -2000, springConstant: 0.04 }}
            }},
            layout: {{ randomSeed: 2 }}
        }};
        const network = new vis.Network(container, data, options);

        // Populate Table (Basic example)
        document.querySelector('tbody').innerHTML = scanData.suggestions.map(s => `
            <tr>
                <td>${{s.node_id}}</td>
                <td class="vuln-high">${{s.label}}</td>
                <td>${{s.impact}} paths broken</td>
            </tr>
        `).join('');

    </script>
</body>
</html>"#, 
    scan.risk_summary.total_bounty,
    scan.risk_summary.critical_paths,
    json_data
    )
}
