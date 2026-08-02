import React, { useEffect, useState } from 'react';
import ReactFlow, { Background, Controls, MarkerType } from 'reactflow';
import type { Edge, Node } from 'reactflow';
import 'reactflow/dist/style.css';
import api from '../../api/client';

interface ThreatGraphProps {
  jobId: string;
}

const ThreatGraph: React.FC<ThreatGraphProps> = ({ jobId }) => {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [edges, setEdges] = useState<Edge[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  useEffect(() => {
    const fetchGraph = async () => {
      try {
        setLoading(true);
        const res = await api.get(`/graph/job/${jobId}`);
        const data = res.data;

        const radius = 250;
        const centerX = 300;
        const centerY = 300;

        const mappedNodes: Node[] = data.nodes.map((n: any, i: number) => {
          const angle = (i / data.nodes.length) * 2 * Math.PI;
          const group = n.data.group;
          
          let label = 'Unknown';
          let bgColor = '#111111';
          let borderColor = '#333333';
          
          if (group === 'Process') {
            label = n.data.executable || `PID: ${n.data.pid}`;
            borderColor = '#ef4444'; // Red
          } else if (group === 'File') {
            label = n.data.filename || n.data.sha256?.substring(0, 8);
            borderColor = '#3b82f6'; // Blue
          } else if (group === 'IPAddress') {
            label = n.data.ip_address;
            borderColor = '#eab308'; // Yellow
          } else if (group === 'AttackTechnique') {
            label = `${n.data.technique_id}: ${n.data.technique_name}`;
            borderColor = '#10b981'; // Green
          } else if (group === 'SandboxJob') {
            label = `Job: ${n.data.job_id.substring(0, 8)}`;
            borderColor = '#ffffff'; // White
          }

          return {
            id: n.data.id,
            position: { 
              x: centerX + Math.cos(angle) * radius, 
              y: centerY + Math.sin(angle) * radius 
            },
            data: { 
              label: (
                <div className="flex flex-col items-center p-1">
                  <span className="text-[9px] text-[#888] uppercase tracking-widest mb-1">{group}</span>
                  <span className="font-bold text-xs font-mono break-all">{label}</span>
                </div>
              ) 
            },
            style: { 
              background: bgColor, 
              color: '#ffffff', 
              border: `1px solid ${borderColor}`,
              borderRadius: '4px',
              minWidth: '120px'
            }
          };
        });

        const mappedEdges: Edge[] = data.edges.map((e: any) => ({
          id: e.data.id,
          source: e.data.source,
          target: e.data.target,
          label: e.data.label,
          labelStyle: { fill: '#888888', fontSize: 10, fontFamily: 'JetBrains Mono', fontWeight: 'bold' },
          labelBgStyle: { fill: '#000000', fillOpacity: 0.8 },
          style: { stroke: '#444444', strokeWidth: 1.5 },
          markerEnd: { type: MarkerType.ArrowClosed, color: '#444444' }
        }));

        setNodes(mappedNodes);
        setEdges(mappedEdges);
      } catch (err) {
        console.error("Failed to load graph", err);
        setError(true);
      } finally {
        setLoading(false);
      }
    };

    if (jobId) {
      fetchGraph();
    }
  }, [jobId]);

  if (loading) {
    return <div className="h-[600px] flex items-center justify-center font-mono text-[#888888] uppercase tracking-widest text-xs border border-[#333333]">Loading Graph Data...</div>;
  }

  if (error || nodes.length === 0) {
    return <div className="h-[600px] flex items-center justify-center font-mono text-[#888888] uppercase tracking-widest text-xs border border-[#333333]">No Graph Data Available for this Analysis.</div>;
  }

  return (
    <div className="h-[600px] border border-[#333333] bg-[#000000]">
      <ReactFlow 
        nodes={nodes} 
        edges={edges} 
        fitView
        className="dark-theme"
      >
        <Background color="#222" gap={16} />
        <Controls className="bg-[#111] border border-[#333] fill-[#fff]" />
      </ReactFlow>
    </div>
  );
};

export default ThreatGraph;
