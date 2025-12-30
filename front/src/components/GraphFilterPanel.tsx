import React from 'react';
import { Filter, Search, AlertTriangle, Server, Globe, Database, X, Check } from 'lucide-react';

export interface GraphFilters {
    showCritical: boolean;
    showHigh: boolean;
    showMedium: boolean;
    showLow: boolean;
    showInfo: boolean;
    showHosts: boolean;
    showServices: boolean;
    showWeb: boolean;
    searchQuery: string;
}

interface Props {
    filters: GraphFilters;
    setFilters: (filters: GraphFilters) => void;
    isOpen: boolean;
    setIsOpen: (isOpen: boolean) => void;
    lang: string;
}

export const GraphFilterPanel: React.FC<Props> = ({ filters, setFilters, isOpen, setIsOpen, lang }) => {
    const isEn = lang === 'en';

    const toggleFilter = (key: keyof GraphFilters) => {
        setFilters({ ...filters, [key]: !filters[key] });
    };

    if (!isOpen) {
        return (
            <button
                onClick={() => setIsOpen(true)}
                className="absolute top-4 right-4 z-10 bg-slate-900/80 backdrop-blur border border-slate-700 p-2 rounded-xl text-slate-400 hover:text-white hover:border-indigo-500 transition-all shadow-xl"
                title={isEn ? "Filter Graph" : "Filtrer le Graphe"}
            >
                <Filter size={20} />
            </button>
        );
    }

    return (
        <div className="absolute top-4 right-4 z-10 bg-slate-900/90 backdrop-blur-md border border-slate-700 p-4 rounded-2xl w-72 shadow-2xl animate-fade-in">
            <div className="flex justify-between items-center mb-4">
                <h3 className="text-xs font-black text-white uppercase tracking-widest flex items-center gap-2">
                    <Filter size={14} className="text-indigo-500" />
                    {isEn ? 'Graph Filters' : 'Filtres Graphiques'}
                </h3>
                <button onClick={() => setIsOpen(false)} className="text-slate-500 hover:text-white">
                    <X size={16} />
                </button>
            </div>

            <div className="space-y-4">
                {/* Search */}
                <div className="relative">
                    <Search size={14} className="absolute left-3 top-2.5 text-slate-500" />
                    <input
                        type="text"
                        value={filters.searchQuery}
                        onChange={(e) => setFilters({ ...filters, searchQuery: e.target.value })}
                        placeholder={isEn ? "Search CVE, Service, IP..." : "Rechercher CVE, Service, IP..."}
                        className="w-full bg-slate-800 border border-slate-700 rounded-lg pl-9 pr-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500 transition-colors placeholder:text-slate-600"
                    />
                </div>

                {/* Severities */}
                <div>
                    <label className="text-[10px] font-bold text-slate-500 uppercase mb-2 block">{isEn ? 'Severity' : 'Sévérité'}</label>
                    <div className="grid grid-cols-2 gap-2">
                        <button
                            onClick={() => toggleFilter('showCritical')}
                            className={`flex items-center gap-2 px-2 py-1.5 rounded-lg text-[10px] font-bold border transition-all ${filters.showCritical ? 'bg-red-500/20 border-red-500 text-red-400' : 'bg-slate-800 border-transparent text-slate-500 grayscale opacity-50'}`}
                        >
                            <div className={`w-2 h-2 rounded-full ${filters.showCritical ? 'bg-red-500' : 'bg-slate-600'}`}></div>
                            CRITICAL
                        </button>
                        <button
                            onClick={() => toggleFilter('showHigh')}
                            className={`flex items-center gap-2 px-2 py-1.5 rounded-lg text-[10px] font-bold border transition-all ${filters.showHigh ? 'bg-orange-500/20 border-orange-500 text-orange-400' : 'bg-slate-800 border-transparent text-slate-500 grayscale opacity-50'}`}
                        >
                            <div className={`w-2 h-2 rounded-full ${filters.showHigh ? 'bg-orange-500' : 'bg-slate-600'}`}></div>
                            HIGH
                        </button>
                        <button
                            onClick={() => toggleFilter('showMedium')}
                            className={`flex items-center gap-2 px-2 py-1.5 rounded-lg text-[10px] font-bold border transition-all ${filters.showMedium ? 'bg-amber-500/20 border-amber-500 text-amber-400' : 'bg-slate-800 border-transparent text-slate-500 grayscale opacity-50'}`}
                        >
                            <div className={`w-2 h-2 rounded-full ${filters.showMedium ? 'bg-amber-500' : 'bg-slate-600'}`}></div>
                            MEDIUM
                        </button>
                        <button
                            onClick={() => toggleFilter('showLow')}
                            className={`flex items-center gap-2 px-2 py-1.5 rounded-lg text-[10px] font-bold border transition-all ${filters.showLow ? 'bg-blue-500/20 border-blue-500 text-blue-400' : 'bg-slate-800 border-transparent text-slate-500 grayscale opacity-50'}`}
                        >
                            <div className={`w-2 h-2 rounded-full ${filters.showLow ? 'bg-blue-500' : 'bg-slate-600'}`}></div>
                            LOW
                        </button>
                    </div>
                </div>

                {/* Node Types */}
                <div>
                    <label className="text-[10px] font-bold text-slate-500 uppercase mb-2 block">{isEn ? 'Node Type' : 'Type de Nœud'}</label>
                    <div className="flex gap-2">
                        <button
                            onClick={() => toggleFilter('showHosts')}
                            className={`flex-1 flex flex-col items-center gap-1 p-2 rounded-xl text-[10px] font-bold border transition-all ${filters.showHosts ? 'bg-indigo-500/20 border-indigo-500 text-indigo-400' : 'bg-slate-800 border-transparent text-slate-500 opacity-50'}`}
                        >
                            <Server size={16} />
                            HOSTS
                        </button>
                        <button
                            onClick={() => toggleFilter('showServices')}
                            className={`flex-1 flex flex-col items-center gap-1 p-2 rounded-xl text-[10px] font-bold border transition-all ${filters.showServices ? 'bg-cyan-500/20 border-cyan-500 text-cyan-400' : 'bg-slate-800 border-transparent text-slate-500 opacity-50'}`}
                        >
                            <Database size={16} />
                            PORTS
                        </button>
                        <button
                            onClick={() => toggleFilter('showWeb')}
                            className={`flex-1 flex flex-col items-center gap-1 p-2 rounded-xl text-[10px] font-bold border transition-all ${filters.showWeb ? 'bg-pink-500/20 border-pink-500 text-pink-400' : 'bg-slate-800 border-transparent text-slate-500 opacity-50'}`}
                        >
                            <Globe size={16} />
                            WEB
                        </button>
                    </div>
                </div>

                <div className="pt-2 border-t border-slate-800 flex justify-end">
                    <button
                        onClick={() => setFilters({
                            showCritical: true, showHigh: true, showMedium: true, showLow: true, showInfo: true,
                            showHosts: true, showServices: true, showWeb: true, searchQuery: ''
                        })}
                        className="text-[10px] font-bold text-slate-500 hover:text-white transition-colors"
                    >
                        {isEn ? 'Reset Default' : 'Réinitialiser'}
                    </button>
                </div>

            </div>
        </div>
    );
};
