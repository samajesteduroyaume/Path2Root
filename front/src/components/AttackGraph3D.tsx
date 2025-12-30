import React, { useRef, useMemo, useCallback } from 'react';
import ForceGraph3D from 'react-force-graph-3d';
import type { Node, Edge } from 'reactflow';

interface Props {
    nodes: Node[];
    edges: Edge[];
    onNodeClick: (node: any) => void;
}

export const AttackGraph3D: React.FC<Props> = ({ nodes, edges, onNodeClick }) => {
    const fgRef = useRef<any>(null);

    const gData = useMemo(() => {
        // DEBUG: Verify props are receiving data
        console.log("AttackGraph3D Renderer:", { nodesCount: nodes.length, edgesCount: edges.length, nodes, edges });

        // Helper: Consistent color generation from string
        const stringToColor = (str: string) => {
            let hash = 0;
            for (let i = 0; i < str.length; i++) {
                hash = str.charCodeAt(i) + ((hash << 5) - hash);
            }
            // HSL generation for better aesthetics (Premium look)
            const h = Math.abs(hash) % 360;
            return `hsl(${h}, 70%, 50%)`;
        };

        return {
            nodes: nodes.map(n => {
                const props = n.data.properties || {};
                const isVulnerable = props.status === 'vulnerable';
                const isCritical = props.is_critical === 'true';
                const nodeType = n.data.node_type;

                // Clustering: Extract parent domain group
                let group = 'other';
                if (n.data.label.includes('.')) {
                    const parts = n.data.label.split('.');
                    if (parts.length >= 2) {
                        // Use last two parts for group (e.g. "google.com")
                        // If IP "192.168.1.1", grouping by subnet logic could be added here
                        group = parts.slice(-2).join('.');
                    }
                }
                const groupColor = stringToColor(group);

                // Heuristics for node size
                let size = 5;
                if (nodeType === 'Internet') size = 12;
                if (nodeType === 'Host') size = 8;
                if (isVulnerable) size = 10;
                if (isCritical) size = 12;
                if (n.id === 'internet') size = 15;

                // Determine final color
                let color = groupColor; // Default to group color
                if (n.id === 'internet') color = '#ffffff';
                else if (isCritical) color = '#eab308'; // Yellow for critical
                else if (isVulnerable) color = '#f97316'; // Orange for vuln
                else if (nodeType === 'Service') color = '#38bdf8'; // Blue for services

                return {
                    id: n.id,
                    label: n.data.label,
                    type: nodeType,
                    group, // Store group for usage
                    color,
                    val: size,
                    properties: props,
                    isCritical
                };
            }),
            links: edges.map(e => ({
                source: e.source,
                target: e.target,
                label: e.label,
                color: nodes.find(n => n.id === e.target)?.data.properties?.is_critical === 'true' ? '#eab308' : '#334155' // Darker slate for normal links
            }))
        };
    }, [nodes, edges]);

    const handleNodeClick = useCallback((node: any) => {
        const originalNode = nodes.find(n => n.id === node.id);
        if (originalNode) {
            onNodeClick(originalNode.data);
        }
    }, [nodes, onNodeClick]);

    const getNodeLabel = useCallback((node: any) => `
        <div style="background: rgba(15, 23, 42, 0.95); border: 1px solid ${node.isCritical ? '#eab308' : '#334155'}; padding: 12px; border-radius: 12px; font-family: sans-serif; min-width: 200px; box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.5);">
            <div style="font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; color: ${node.isCritical ? '#eab308' : '#94a3b8'}; font-weight: 800; margin-bottom: 4px;">
                ${node.isCritical ? '🔥 CRITICAL PATH' : node.type}
            </div>
            <div style="font-size: 14px; font-weight: 900; color: #fff; margin-bottom: 8px;">${node.label}</div>
            
            ${node.properties.ip ? `<div style="display: flex; justify-between; font-size: 11px; margin-bottom: 4px;"><span style="color: #64748b;">IP Address:</span> <span style="color: #cbd5e1; font-family: monospace;">${node.properties.ip}</span></div>` : ''}
            ${node.properties.os ? `<div style="display: flex; justify-between; font-size: 11px; margin-bottom: 4px;"><span style="color: #64748b;">OS:</span> <span style="color: #10b981; font-weight: bold;">${node.properties.os}</span></div>` : ''}
            ${node.properties.service ? `<div style="display: flex; justify-between; font-size: 11px; margin-bottom: 4px;"><span style="color: #64748b;">Service:</span> <span style="color: #38bdf8;">${node.properties.service}:${node.properties.port}</span></div>` : ''}
            
            ${node.properties.status === 'vulnerable' ? `
                <div style="margin-top: 10px; padding: 8px; background: rgba(249, 115, 22, 0.1); border: 1px solid rgba(249, 115, 22, 0.3); border-radius: 8px;">
                    <div style="color: #fb923c; font-size: 10px; font-weight: 800; text-transform: uppercase;">⚠️ Potential Vulnerability</div>
                    <div style="color: #fff; font-size: 11px; margin-top: 4px;">${node.properties.finding || 'Criticity detected'}</div>
                    ${node.properties.cvss ? `<div style="color: #fca5a5; font-size: 9px; margin-top: 2px;">CVSS Score: ${node.properties.cvss}</div>` : ''}
                </div>
            ` : ''}
        </div>
    `, []);

    return (
        <div className="w-full h-full bg-slate-950">
            <ForceGraph3D
                ref={fgRef}
                graphData={gData}
                nodeLabel={getNodeLabel}
                nodeColor={(node: any) => node.color}
                nodeRelSize={1}
                nodeVal={(node: any) => node.val}
                linkDirectionalArrowLength={3.5}
                linkDirectionalArrowRelPos={1}
                linkCurvature={0.25}
                linkColor={(link: any) => link.color}
                onNodeClick={handleNodeClick}
                backgroundColor="#020617"
                cooldownTicks={100}
                d3AlphaDecay={0.02}
            />
        </div>
    );
};
