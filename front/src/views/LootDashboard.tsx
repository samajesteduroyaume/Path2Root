import React, { useState, useMemo } from 'react';
import { Database, Key, Shield, FileText, AlertTriangle, Eye, Lock, Search, CheckCircle, Info, Download } from 'lucide-react';

interface LootItem {
    id: string;
    label: string;
    type: string;
    properties: any;
}

interface LootDashboardProps {
    nodes: LootItem[];
    lang: string;
}

const LootDashboard: React.FC<LootDashboardProps> = ({ nodes, lang }) => {
    const isEn = lang === 'en';
    const [searchQuery, setSearchQuery] = useState('');
    const [filterType, setFilterType] = useState<string>('all');

    // Filtrer les nœuds qui contiennent du "loot"
    const allLoot = useMemo(() => {
        return nodes.filter(node => {
            const p = node.properties || {};
            const isSensitiveType = node.type === 'User' || node.type === 'Data';
            const isVulnerable = p.status === 'vulnerable';
            const hasSecrets = p.finding?.toLowerCase().includes('key') ||
                p.finding?.toLowerCase().includes('password') ||
                p.banner?.toLowerCase().includes('secret') ||
                p.exploit_url;
            return isSensitiveType || isVulnerable || hasSecrets;
        });
    }, [nodes]);

    const filteredLoot = useMemo(() => {
        return allLoot.filter(node => {
            const matchesSearch =
                node.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
                JSON.stringify(node.properties).toLowerCase().includes(searchQuery.toLowerCase());

            const matchesType = filterType === 'all' || node.type === filterType;

            return matchesSearch && matchesType;
        });
    }, [allLoot, searchQuery, filterType]);

    const getStatusBadge = (node: any) => {
        const p = node.properties || {};
        if (p.is_critical === 'true' || parseInt(p.exploit_impact || '0') >= 9) {
            return <span className="px-2 py-0.5 bg-red-500/20 text-red-400 text-[10px] font-black rounded border border-red-500/30 uppercase animate-pulse">Critical</span>;
        }
        if (p.status === 'vulnerable') {
            return <span className="px-2 py-0.5 bg-amber-500/20 text-amber-400 text-[10px] font-black rounded border border-amber-500/30 uppercase">Vulnerable</span>;
        }
        return <span className="px-2 py-0.5 bg-indigo-500/20 text-indigo-400 text-[10px] font-black rounded border border-indigo-500/30 uppercase">Secured</span>;
    };

    return (
        <div className="space-y-8 animate-fade-in">
            <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6">
                <div>
                    <h1 className="text-4xl font-black text-white flex items-center gap-4">
                        <div className="w-12 h-12 bg-fuchsia-600 rounded-2xl flex items-center justify-center shadow-lg shadow-fuchsia-600/20">
                            <Lock size={28} className="text-white" />
                        </div>
                        {isEn ? 'Loot & Intelligence' : 'Butin & Intelligence'}
                    </h1>
                    <p className="text-slate-500 font-bold uppercase text-xs mt-2 tracking-widest flex items-center gap-2">
                        <Shield size={14} />
                        {isEn ? 'Evidence, Credentials & High-Value Assets' : 'Preuves, Identifiants & Actifs Haute Valeur'}
                    </p>
                </div>
                <div className="flex gap-3">
                    <div className="px-6 py-3 bg-fuchsia-500/10 border border-fuchsia-500/20 rounded-2xl flex items-center gap-3 backdrop-blur-md">
                        <AlertTriangle size={20} className="text-fuchsia-500" />
                        <div>
                            <div className="text-[10px] font-black text-fuchsia-500/50 uppercase leading-none mb-1">Total Evidence</div>
                            <div className="text-sm font-black text-fuchsia-400 leading-none">{allLoot.length} ITEMS</div>
                        </div>
                    </div>
                </div>
            </div>

            {/* Barre de Recherche & Filtres */}
            <div className="flex flex-col md:flex-row gap-4 p-4 bg-slate-900/50 border border-slate-800 rounded-2xl backdrop-blur-xl">
                <div className="relative flex-1">
                    <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                    <input
                        type="text"
                        placeholder={isEn ? "Search across loot properties..." : "Chercher dans les propriétés du butin..."}
                        className="w-full pl-12 pr-4 py-3 bg-slate-950 border border-slate-800 rounded-xl text-xs font-bold text-white focus:outline-none focus:border-fuchsia-500 transition-all"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                    />
                </div>
                <div className="flex gap-2">
                    <select
                        className="px-4 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs font-bold text-slate-400 focus:outline-none focus:border-fuchsia-500"
                        value={filterType}
                        onChange={(e) => setFilterType(e.target.value)}
                    >
                        <option value="all">{isEn ? 'All Types' : 'Tous les Types'}</option>
                        <option value="User">{isEn ? 'Credentials' : 'Identifiants'}</option>
                        <option value="Data">{isEn ? 'Sensitive Data' : 'Données Sensibles'}</option>
                        <option value="Service">{isEn ? 'Vulnerable Services' : 'Services Vulnérables'}</option>
                    </select>
                    <button className="p-3 bg-slate-950 border border-slate-800 rounded-xl text-slate-400 hover:text-white hover:border-slate-700 transition-all">
                        <Download size={18} />
                    </button>
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {filteredLoot.length === 0 ? (
                    <div className="col-span-full p-20 bg-slate-900/50 border border-dashed border-slate-800 rounded-3xl text-center space-y-4">
                        <div className="w-20 h-20 bg-slate-800/30 rounded-full flex items-center justify-center mx-auto mb-6">
                            <Shield className="text-slate-700" size={40} />
                        </div>
                        <h3 className="text-xl font-bold text-slate-400">{isEn ? 'No evidence matches your search.' : 'Aucune preuve ne correspond à votre recherche.'}</h3>
                        <p className="text-slate-500 text-sm max-w-md mx-auto">{isEn ? 'Try adjusting your filters or launch a new mission.' : 'Essayez d\'ajuster vos filtres ou lancez une nouvelle mission.'}</p>
                    </div>
                ) : (
                    filteredLoot.map((node) => (
                        <div key={node.id} className="p-6 bg-slate-900/80 border border-slate-800 rounded-3xl hover:border-fuchsia-500 transition-all group relative overflow-hidden backdrop-blur-sm">
                            <div className="absolute top-0 right-0 w-32 h-32 bg-fuchsia-500/5 rotate-45 translate-x-16 -translate-y-16 group-hover:bg-fuchsia-500/10 transition-all"></div>

                            <div className="flex justify-between items-start mb-6">
                                <div className={`p-4 rounded-2xl shadow-inner ${node.type === 'User' ? 'bg-indigo-500/20 text-indigo-400' : 'bg-fuchsia-500/20 text-fuchsia-400'}`}>
                                    {node.type === 'User' ? <Key size={26} /> : <Database size={26} />}
                                </div>
                                <div className="flex flex-col items-end gap-2">
                                    <span className="text-[9px] font-black px-2 py-1 bg-slate-800 rounded text-slate-500 uppercase tracking-widest border border-slate-700/50">
                                        ID: {node.id.substring(0, 8)}
                                    </span>
                                    {getStatusBadge(node)}
                                </div>
                            </div>

                            <h3 className="text-xl font-black text-white mb-2 truncate group-hover:text-fuchsia-400 transition-colors">{node.label}</h3>
                            <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest mb-4 flex items-center gap-1">
                                <Info size={10} />
                                {node.type} discovered on network
                            </p>

                            <div className="space-y-2">
                                {Object.entries(node.properties || {})
                                    .filter(([k]) => ['username', 'password', 'key', 'cvss', 'port', 'service', 'banner'].includes(k))
                                    .map(([key, value]: [string, any]) => (
                                        <div key={key} className="p-3 bg-black/40 rounded-xl border border-slate-800/50 hover:border-slate-700 transition-all">
                                            <div className="flex justify-between items-center mb-1">
                                                <span className="text-[9px] text-fuchsia-500 font-black uppercase tracking-widest">{key}</span>
                                                {key === 'cvss' && <div className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse"></div>}
                                            </div>
                                            <span className="text-xs font-mono text-slate-300 break-all leading-relaxed">{value}</span>
                                        </div>
                                    ))}
                            </div>

                            <div className="mt-8 pt-6 border-t border-slate-800/50 flex justify-between items-center">
                                <div className="flex items-center gap-2">
                                    <CheckCircle size={16} className="text-green-500" />
                                    <span className="text-[10px] text-slate-400 font-black uppercase tracking-tighter">{isEn ? 'VERIFIED EVIDENCE' : 'PREUVE VÉRIFIÉE'}</span>
                                </div>
                                <div className="flex gap-2">
                                    <button className="p-2 hover:bg-slate-800 rounded-xl text-slate-500 hover:text-white transition-all">
                                        <Eye size={18} />
                                    </button>
                                    <button className="p-2 bg-fuchsia-500/10 hover:bg-fuchsia-500/20 rounded-xl text-fuchsia-500 transition-all border border-fuchsia-500/20">
                                        <FileText size={18} />
                                    </button>
                                </div>
                            </div>
                        </div>
                    ))
                )}
            </div>
        </div>
    );
};

export default LootDashboard;
