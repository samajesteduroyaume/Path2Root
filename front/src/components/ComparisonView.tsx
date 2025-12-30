import React from 'react';
import { Shield, Target, Plus, Minus, ArrowRight, AlertCircle, CheckCircle } from 'lucide-react';

interface Props {
    data: any;
    onClose: () => void;
    lang: string;
}

export const ComparisonView: React.FC<Props> = ({ data, onClose, lang }) => {
    const isEn = lang === 'en';
    const { mission1, mission2, comparison } = data;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-fade-in">
            <div className="bg-slate-900 border border-slate-700 w-full max-w-5xl max-h-[90vh] rounded-3xl overflow-hidden flex flex-col shadow-2xl">
                {/* Header */}
                <div className="p-6 border-b border-slate-800 flex justify-between items-center bg-slate-950">
                    <div>
                        <h2 className="text-2xl font-black text-white flex items-center gap-3">
                            <Shield className="text-indigo-500" />
                            {isEn ? 'Tactical Comparison Analysis' : 'Analyse Comparative Tactique'}
                        </h2>
                        <p className="text-slate-500 text-sm mt-1">
                            {isEn ? `Comparing Mission ${mission1.id} vs ${mission2.id}` : `Comparaison Mission ${mission1.id} vs ${mission2.id}`}
                        </p>
                    </div>
                    <button
                        onClick={onClose}
                        className="p-2 hover:bg-slate-800 rounded-lg text-slate-400 hover:text-white transition-colors"
                    >
                        <ArrowRight size={24} />
                    </button>
                </div>

                {/* Content */}
                <div className="flex-1 overflow-y-auto p-6 space-y-8 custom-scrollbar">

                    {/* Stats Bar */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div className="p-4 bg-slate-950/50 rounded-2xl border border-slate-800 flex flex-col items-center justify-center text-center">
                            <span className="text-xs text-slate-500 font-bold uppercase mb-1">{isEn ? 'New Vulnerabilities' : 'Nouvelles Vulnérabilités'}</span>
                            <span className="text-3xl font-black text-red-500 flex items-center gap-2">
                                <Plus size={20} /> {comparison.new_count}
                            </span>
                        </div>
                        <div className="p-4 bg-slate-950/50 rounded-2xl border border-slate-800 flex flex-col items-center justify-center text-center">
                            <span className="text-xs text-slate-500 font-bold uppercase mb-1">{isEn ? 'Resolved Issues' : 'Problèmes Résolus'}</span>
                            <span className="text-3xl font-black text-emerald-500 flex items-center gap-2">
                                <CheckCircle size={20} /> {comparison.resolved_count}
                            </span>
                        </div>
                        <div className="p-4 bg-slate-950/50 rounded-2xl border border-slate-800 flex flex-col items-center justify-center text-center">
                            <span className="text-xs text-slate-500 font-bold uppercase mb-1">{isEn ? 'Persistent Issues' : 'Problèmes Persistants'}</span>
                            <span className="text-3xl font-black text-slate-400 flex items-center gap-2">
                                <AlertCircle size={20} /> {comparison.common_count}
                            </span>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                        {/* New Findings */}
                        <div className="space-y-4">
                            <h3 className="text-sm font-black text-red-500 uppercase tracking-widest flex items-center gap-2 border-b border-red-500/20 pb-2">
                                <Plus size={16} /> {isEn ? 'New Threats Detected' : 'Nouvelles Menaces Détectées'}
                            </h3>
                            {comparison.new_findings.length === 0 ? (
                                <div className="p-8 text-center text-slate-600 text-sm italic">{isEn ? 'No new threats found.' : 'Aucune nouvelle menace.'}</div>
                            ) : (
                                <div className="space-y-3">
                                    {comparison.new_findings.map((f: any, i: number) => (
                                        <div key={i} className="p-4 bg-red-500/5 border border-red-500/20 rounded-xl">
                                            <div className="flex justify-between items-start">
                                                <div className="font-bold text-red-400">{f.title}</div>
                                                <span className="px-2 py-0.5 bg-red-500/20 text-red-400 text-[10px] font-black uppercase rounded">{f.severity}</span>
                                            </div>
                                            <div className="text-xs text-slate-400 mt-1">{f.description?.substring(0, 100)}...</div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>

                        {/* Resolved Findings */}
                        <div className="space-y-4">
                            <h3 className="text-sm font-black text-emerald-500 uppercase tracking-widest flex items-center gap-2 border-b border-emerald-500/20 pb-2">
                                <CheckCircle size={16} /> {isEn ? 'Successful Remediations' : 'Remédiations Réussies'}
                            </h3>
                            {comparison.resolved_findings.length === 0 ? (
                                <div className="p-8 text-center text-slate-600 text-sm italic">{isEn ? 'No remediations confirmed.' : 'Aucune remédiation confirmée.'}</div>
                            ) : (
                                <div className="space-y-3">
                                    {comparison.resolved_findings.map((f: any, i: number) => (
                                        <div key={i} className="p-4 bg-emerald-500/5 border border-emerald-500/20 rounded-xl opacity-75">
                                            <div className="flex justify-between items-start">
                                                <div className="font-bold text-emerald-400 line-through">{f.title}</div>
                                                <span className="px-2 py-0.5 bg-emerald-500/20 text-emerald-400 text-[10px] font-black uppercase rounded">PATCHED</span>
                                            </div>
                                            <div className="text-xs text-slate-500 mt-1">{isEn ? 'Vulnerability no longer present in latest scan.' : 'Vulnérabilité absente du dernier scan.'}</div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    </div>

                </div>
            </div>
        </div>
    );
};
