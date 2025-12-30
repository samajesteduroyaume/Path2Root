import React, { useState } from 'react';
import { Search, Shield, Server, User, Globe, Activity, ArrowRight, Download } from 'lucide-react';

interface Node {
    id: string;
    label: string;
    node_type: string;
    properties: Record<string, string>;
}

interface Props {
    nodes: Node[];
    onSelectNode: (nodeId: string) => void;
    lang: string;
}

export const AssetInventory: React.FC<Props> = ({ nodes, onSelectNode, lang }) => {
    const [searchTerm, setSearchTerm] = useState('');
    const [filterType, setFilterType] = useState<string | null>(null);
    const isEn = lang === 'en';

    const filteredNodes = nodes.filter(n => {
        const matchesSearch = n.label.toLowerCase().includes(searchTerm.toLowerCase()) ||
            n.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
            Object.values(n.properties).some(v => v.toLowerCase().includes(searchTerm.toLowerCase()));
        const matchesFilter = !filterType || n.node_type === filterType;
        return matchesSearch && matchesFilter;
    });

    const getTypeIcon = (type: string) => {
        switch (type) {
            case 'Host': return <Server size={16} className="text-purple-400" />;
            case 'Service': return <Globe size={16} className="text-blue-400" />;
            case 'User': return <User size={16} className="text-cyan-400" />;
            case 'Internet': return <Activity size={16} className="text-green-400" />;
            default: return <Shield size={16} className="text-slate-400" />;
        }
    };

    return (
        <div className="p-8 space-y-6 bg-slate-950 min-h-full">
            <div className="flex justify-between items-center">
                <div>
                    <h1 className="text-3xl font-black text-white flex items-center gap-3">
                        <Shield className="text-indigo-500" size={32} />
                        {isEn ? 'Asset Inventory' : 'Inventaire des Actifs'}
                    </h1>
                    <p className="text-slate-500 font-bold uppercase text-xs mt-1 tracking-widest">
                        {isEn ? 'Centralized management of discovered infrastructure' : 'Gestion centralisée de l\'infrastructure découverte'}
                    </p>
                </div>
                <div className="flex gap-3">
                    <button className="flex items-center gap-2 px-4 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs font-bold text-slate-400 hover:text-white transition-all">
                        <Download size={14} /> CSV
                    </button>
                </div>
            </div>

            <div className="flex gap-4">
                <div className="flex-1 relative">
                    <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                    <input
                        type="text"
                        placeholder={isEn ? "Search assets, IPs, technologies..." : "Rechercher actifs, IPs, technologies..."}
                        className="w-full pl-12 pr-4 py-3 bg-slate-900 border border-slate-800 rounded-2xl text-sm text-white focus:outline-none focus:border-indigo-500 transition-all font-medium"
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                    />
                </div>
                <div className="flex gap-2">
                    {['Host', 'Service', 'User', 'Data'].map(type => (
                        <button
                            key={type}
                            onClick={() => setFilterType(filterType === type ? null : type)}
                            className={`px-4 py-2 rounded-xl text-[10px] font-black uppercase tracking-tight transition-all border ${filterType === type ? 'bg-indigo-600 border-indigo-500 text-white' : 'bg-slate-900 border-slate-800 text-slate-500 hover:border-slate-700'}`}
                        >
                            {type}s
                        </button>
                    ))}
                </div>
            </div>

            <div className="bg-slate-900/50 border border-slate-800 rounded-3xl overflow-hidden glass-panel">
                <table className="w-full text-left">
                    <thead>
                        <tr className="border-b border-slate-800 bg-slate-900/50">
                            <th className="px-6 py-4 text-[10px] font-black uppercase text-slate-500 tracking-widest">{isEn ? 'Asset / Identity' : 'Actif / Identité'}</th>
                            <th className="px-6 py-4 text-[10px] font-black uppercase text-slate-500 tracking-widest">Type</th>
                            <th className="px-6 py-4 text-[10px] font-black uppercase text-slate-500 tracking-widest">{isEn ? 'Technology Stack' : 'Stack Technologique'}</th>
                            <th className="px-6 py-4 text-[10px] font-black uppercase text-slate-500 tracking-widest">Status</th>
                            <th className="px-6 py-4 text-[10px] font-black uppercase text-slate-500 tracking-widest text-right">Action</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                        {filteredNodes.length === 0 ? (
                            <tr>
                                <td colSpan={5} className="px-6 py-20 text-center text-slate-600 font-bold uppercase text-xs tracking-tighter">
                                    {isEn ? 'No assets match your criteria' : 'Aucun actif ne correspond à vos critères'}
                                </td>
                            </tr>
                        ) : filteredNodes.map(node => (
                            <tr key={node.id} className="group hover:bg-slate-800/30 transition-all">
                                <td className="px-6 py-4">
                                    <div className="flex items-center gap-3">
                                        <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${node.properties.is_critical === 'true' ? 'bg-red-500/10 text-red-500 pulse-critical' : 'bg-slate-800 text-slate-400'}`}>
                                            {getTypeIcon(node.node_type)}
                                        </div>
                                        <div>
                                            <div className="text-xs font-black text-white group-hover:text-indigo-400 transition-colors">{node.label}</div>
                                            <div className="text-[10px] text-slate-500 font-mono">{node.id}</div>
                                        </div>
                                    </div>
                                </td>
                                <td className="px-6 py-4">
                                    <span className="px-2 py-0.5 bg-slate-800 text-slate-400 text-[10px] font-bold rounded uppercase">{node.node_type}</span>
                                </td>
                                <td className="px-6 py-4">
                                    <div className="flex flex-wrap gap-1">
                                        {node.properties.cms && <span className="px-2 py-0.5 bg-indigo-500/10 text-indigo-400 text-[10px] font-bold rounded">{node.properties.cms}</span>}
                                        {node.properties.framework && <span className="px-2 py-0.5 bg-cyan-500/10 text-cyan-400 text-[10px] font-bold rounded">{node.properties.framework}</span>}
                                        {node.properties.waf && <span className="px-2 py-0.5 bg-amber-500/10 text-amber-500 text-[10px] font-bold rounded">{node.properties.waf}</span>}
                                        {!node.properties.cms && !node.properties.framework && !node.properties.waf && <span className="text-[10px] text-slate-600">—</span>}
                                    </div>
                                </td>
                                <td className="px-6 py-4">
                                    {node.properties.status === 'vulnerable' ? (
                                        <span className="px-2 py-0.5 bg-red-500/10 text-red-500 text-[10px] font-black rounded uppercase flex items-center gap-1 w-fit">
                                            Vulnerable
                                        </span>
                                    ) : (
                                        <span className="px-2 py-0.5 bg-green-500/10 text-green-500 text-[10px] font-black rounded uppercase flex items-center gap-1 w-fit">
                                            Secure
                                        </span>
                                    )}
                                </td>
                                <td className="px-6 py-4 text-right">
                                    <button
                                        onClick={() => onSelectNode(node.id)}
                                        className="p-2 text-slate-600 hover:text-white hover:bg-slate-800 rounded-lg transition-all"
                                    >
                                        <ArrowRight size={16} />
                                    </button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
};
