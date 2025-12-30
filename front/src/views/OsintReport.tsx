import React from 'react';
import { Globe, MapPin, Share2, Shield, Database, Activity, Compass } from 'lucide-react';

interface Node {
    id: string;
    label: string;
    node_type: string;
    properties: Record<string, string>;
}

interface Props {
    nodes: Node[];
    lang: string;
}

export const OsintReport: React.FC<Props> = ({ nodes, lang }) => {
    const isEn = lang === 'en';

    const hosts = nodes.filter(n => n.node_type === 'Host');
    const subdomains = nodes.filter(n => n.properties.type === 'subdomain');
    const criticalGeo = nodes.filter(n => n.properties.country || n.properties.city);

    return (
        <div className="p-8 space-y-8 bg-slate-950 min-h-full">
            <div className="flex justify-between items-end">
                <div>
                    <h1 className="text-3xl font-black text-white flex items-center gap-3">
                        <Compass className="text-sky-500" size={32} />
                        {isEn ? 'Strategic Resource Intel' : 'Renseignement de Ressources Stratégiques'}
                    </h1>
                    <p className="text-slate-500 font-bold uppercase text-xs mt-1 tracking-widest">
                        {isEn ? 'Passive OSINT & Infrastructure Map' : 'OSINT Passif & Cartographie d\'Infrastructure'}
                    </p>
                </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {/* Stats Cards */}
                <div className="bg-slate-900/50 p-6 rounded-3xl border border-slate-800 glass-panel">
                    <div className="flex items-center gap-4 mb-4">
                        <div className="p-3 bg-sky-500/10 rounded-2xl text-sky-500">
                            <Share2 size={24} />
                        </div>
                        <div>
                            <div className="text-[10px] font-black uppercase text-slate-500 tracking-widest">{isEn ? 'Discovery' : 'Découverte'}</div>
                            <div className="text-2xl font-black text-white">{subdomains.length}</div>
                        </div>
                    </div>
                    <div className="text-xs font-bold text-slate-400">
                        {isEn ? 'Passive subdomains via crt.sh' : 'Sous-domaines passifs via crt.sh'}
                    </div>
                </div>

                <div className="bg-slate-900/50 p-6 rounded-3xl border border-slate-800 glass-panel">
                    <div className="flex items-center gap-4 mb-4">
                        <div className="p-3 bg-indigo-500/10 rounded-2xl text-indigo-500">
                            <Globe size={24} />
                        </div>
                        <div>
                            <div className="text-[10px] font-black uppercase text-slate-500 tracking-widest">{isEn ? 'Global Reach' : 'Portée Globale'}</div>
                            <div className="text-2xl font-black text-white">{new Set(hosts.map(h => h.properties.country).filter(Boolean)).size}</div>
                        </div>
                    </div>
                    <div className="text-xs font-bold text-slate-400">
                        {isEn ? 'Unique Countries Identified' : 'Pays uniques identifiés'}
                    </div>
                </div>

                <div className="bg-slate-900/50 p-6 rounded-3xl border border-slate-800 glass-panel">
                    <div className="flex items-center gap-4 mb-4">
                        <div className="p-3 bg-amber-500/10 rounded-2xl text-amber-500">
                            <Database size={24} />
                        </div>
                        <div>
                            <div className="text-[10px] font-black uppercase text-slate-500 tracking-widest">{isEn ? 'Intel Records' : 'Enregistrements Intel'}</div>
                            <div className="text-2xl font-black text-white">{hosts.filter(h => h.properties.shodan_intel).length}</div>
                        </div>
                    </div>
                    <div className="text-xs font-bold text-slate-400">
                        {isEn ? 'Shodan / OSINT data points' : 'Points de données Shodan / OSINT'}
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                {/* Geolocation Table */}
                <div className="bg-slate-900/50 rounded-3xl border border-slate-800 overflow-hidden glass-panel">
                    <div className="p-6 border-b border-slate-800 flex items-center justify-between">
                        <h2 className="text-sm font-black text-white uppercase flex items-center gap-2">
                            <MapPin size={16} className="text-red-500" />
                            {isEn ? 'Infrastructure Geolocation' : 'Géolocalisation d\'Infrastructure'}
                        </h2>
                    </div>
                    <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs">
                            <thead>
                                <tr className="bg-slate-900/50 border-b border-slate-800 text-slate-500 font-black uppercase text-[10px]">
                                    <th className="px-6 py-4">{isEn ? 'Target IP' : 'IP Cible'}</th>
                                    <th className="px-6 py-4">{isEn ? 'Location' : 'Emplacement'}</th>
                                    <th className="px-6 py-4">ISP</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-800/50">
                                {criticalGeo.length === 0 ? (
                                    <tr><td colSpan={3} className="px-6 py-12 text-center text-slate-600 font-bold uppercase">{isEn ? 'No location data found' : 'Aucune donnée de localisation'}</td></tr>
                                ) : criticalGeo.map(h => (
                                    <tr key={h.id} className="hover:bg-slate-800/20 transition-all">
                                        <td className="px-6 py-4 font-mono text-indigo-400">{h.properties.ip || h.id}</td>
                                        <td className="px-6 py-4 text-white font-bold">
                                            {h.properties.city}, {h.properties.country}
                                        </td>
                                        <td className="px-6 py-4 text-slate-400">{h.properties.isp || 'N/A'}</td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>

                {/* Subdomain Tree Visualization Placeholder */}
                <div className="bg-slate-900/50 rounded-3xl border border-slate-800 p-6 flex flex-col glass-panel">
                    <h2 className="text-sm font-black text-white uppercase flex items-center gap-2 mb-6">
                        <Share2 size={16} className="text-sky-500" />
                        {isEn ? 'Attack Surface (Subdomains)' : 'Surface d\'Attaque (Sous-domaines)'}
                    </h2>
                    <div className="flex-1 space-y-3 overflow-y-auto max-h-[400px] pr-2 custom-scrollbar">
                        {subdomains.length === 0 ? (
                            <div className="h-full flex items-center justify-center text-center text-slate-700 italic border-4 border-dashed border-slate-800/50 rounded-2xl p-8">
                                {isEn ? 'Run a scan on a domain to discover subdomains passively' : 'Lancez un scan sur un domaine pour découvrir les sous-domaines passivement'}
                            </div>
                        ) : subdomains.map(s => (
                            <div key={s.id} className="p-3 bg-slate-800/50 border border-slate-800 rounded-xl flex items-center justify-between group hover:border-sky-500/50 transition-all">
                                <div className="flex items-center gap-3">
                                    <div className="w-2 h-2 rounded-full bg-sky-500 shadow-[0_0_8px_rgba(14,165,233,0.5)]"></div>
                                    <span className="text-xs font-bold text-slate-300 group-hover:text-white">{s.label}</span>
                                </div>
                                <span className="text-[10px] px-2 py-0.5 bg-slate-900 text-slate-600 rounded">PASSIVE</span>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* Shodan/Threat Intel Stubs */}
            <div className="bg-slate-900/50 p-6 rounded-3xl border border-slate-800 glass-panel">
                <h2 className="text-sm font-black text-white uppercase flex items-center gap-2 mb-4">
                    <Activity size={16} className="text-indigo-400" />
                    {isEn ? 'Threat Intelligence Records' : 'Renseignements sur les Menaces'}
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {hosts.filter(h => h.properties.shodan_intel).map(h => (
                        <div key={h.id} className="p-4 bg-indigo-950/20 border border-indigo-500/20 rounded-2xl">
                            <div className="text-xs font-black text-indigo-400 mb-2 uppercase tracking-tighter">Record for {h.id}</div>
                            <ul className="space-y-1">
                                {h.properties.shodan_intel.split(' | ').map((intel, idx) => (
                                    <li key={idx} className="text-[10px] text-slate-400 flex items-center gap-2">
                                        <Shield size={10} className="text-indigo-600" />
                                        {intel}
                                    </li>
                                ))}
                            </ul>
                        </div>
                    ))}
                    {hosts.filter(h => h.properties.shodan_intel).length === 0 && (
                        <div className="col-span-2 py-8 text-center text-slate-700 text-xs font-bold uppercase italic">
                            {isEn ? 'No external intel records available' : 'Aucun enregistrement d\'intel externe disponible'}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};
