import React from 'react';
import { Target, Zap, ExternalLink, AlertTriangle, Crosshair, Terminal } from 'lucide-react';

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

export const AttackJourney: React.FC<Props> = ({ nodes, lang }) => {
    const isEn = lang === 'en';

    // Filtrer et trier les nœuds du chemin critique par étape de la Kill Chain
    const journeySteps = nodes
        .filter(n => n.properties.is_critical === "true" || n.properties.kill_chain_stage)
        .sort((a, b) => {
            const stages = ["Initial Access", "Persistence/Pivot", "Lateral Movement", "Exfiltration/Objective"];
            return stages.indexOf(a.properties.kill_chain_stage || "") - stages.indexOf(b.properties.kill_chain_stage || "");
        });

    const getStageColor = (stage: string) => {
        switch (stage) {
            case "Initial Access": return "text-sky-400 bg-sky-400/10 border-sky-400/20";
            case "Persistence/Pivot": return "text-indigo-400 bg-indigo-400/10 border-indigo-400/20";
            case "Lateral Movement": return "text-orange-400 bg-orange-400/10 border-orange-400/20";
            case "Exfiltration/Objective": return "text-red-400 bg-red-400/10 border-red-400/20";
            default: return "text-slate-400 bg-slate-400/10 border-slate-400/20";
        }
    };

    return (
        <div className="p-8 space-y-8 bg-slate-950 min-h-full">
            <div className="flex justify-between items-end">
                <div>
                    <h1 className="text-3xl font-black text-white flex items-center gap-3">
                        <Zap className="text-amber-500" size={32} />
                        {isEn ? 'Path of Least Resistance' : 'Chemin de Moindre Résistance'}
                    </h1>
                    <p className="text-slate-500 font-bold uppercase text-xs mt-1 tracking-widest">
                        {isEn ? 'Dynamic Attack Journey Simulation' : 'Simulation Dynamique du Parcours d\'Attaque'}
                    </p>
                </div>
            </div>

            <div className="max-w-3xl mx-auto">
                {journeySteps.length === 0 ? (
                    <div className="py-20 text-center space-y-4">
                        <div className="w-16 h-16 bg-slate-900 rounded-full flex items-center justify-center mx-auto text-slate-700">
                            <Crosshair size={32} />
                        </div>
                        <p className="text-slate-500 font-bold italic uppercase text-sm">
                            {isEn ? 'No critical path identified. Run a deep scan to simulate journeys.' : 'Aucun chemin critique identifié. Lancez un scan profond pour simuler.'}
                        </p>
                    </div>
                ) : (
                    <div className="relative space-y-12 before:absolute before:inset-0 before:ml-5 before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-slate-800 before:to-transparent">
                        {journeySteps.map((step, idx) => (
                            <div key={step.id} className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group">
                                {/* Dot */}
                                <div className="flex items-center justify-center w-10 h-10 rounded-full border border-slate-700 bg-black text-slate-300 shadow shrink-0 md:order-1 md:group-odd:-translate-x-1/2 md:group-even:translate-x-1/2 z-10 transition-all group-hover:border-amber-500/50 group-hover:scale-110">
                                    {idx + 1}
                                </div>

                                {/* Content Card */}
                                <div className="w-[calc(100%-4rem)] md:w-[calc(50%-2.5rem)] p-6 rounded-3xl bg-slate-900/50 border border-slate-800 glass-panel group-hover:border-slate-600 transition-all">
                                    <div className="flex items-center justify-between mb-4">
                                        <div className={`text-[10px] px-2 py-1 rounded-lg border font-black uppercase tracking-tighter ${getStageColor(step.properties.kill_chain_stage || "")}`}>
                                            {step.properties.kill_chain_stage || "Discovery"}
                                        </div>
                                        {step.properties.exploit_complexity && (
                                            <div className="flex gap-1">
                                                {[...Array(5)].map((_, i) => (
                                                    <div key={i} className={`w-1.5 h-1.5 rounded-full ${i < (11 - parseInt(step.properties.exploit_complexity)) / 2 ? 'bg-amber-500' : 'bg-slate-800'}`}></div>
                                                ))}
                                            </div>
                                        )}
                                    </div>

                                    <h3 className="text-lg font-black text-white mb-2">{step.label}</h3>

                                    {step.properties.exploit_name && (
                                        <div className="p-4 bg-indigo-500/5 border border-indigo-500/10 rounded-2xl space-y-3 mb-4">
                                            <div className="flex items-center gap-2 text-indigo-400">
                                                <Target size={14} />
                                                <span className="text-xs font-black uppercase tracking-widest">{isEn ? 'Exploit Available' : 'Exploit Disponible'}</span>
                                            </div>
                                            <div className="text-xs text-slate-300 font-bold leading-relaxed">{step.properties.exploit_name}</div>
                                            {step.properties.exploit_url && (
                                                <a
                                                    href={step.properties.exploit_url}
                                                    target="_blank"
                                                    rel="noreferrer"
                                                    className="flex items-center gap-2 text-[10px] text-slate-500 hover:text-indigo-400 transition-colors mt-2"
                                                >
                                                    <ExternalLink size={10} />
                                                    {isEn ? 'View Technical Details' : 'Détails Techniques'}
                                                </a>
                                            )}
                                        </div>
                                    )}

                                    <div className="flex gap-4">
                                        <div className="flex-1">
                                            <div className="text-[9px] text-slate-600 font-black uppercase mb-1">Impact</div>
                                            <div className="h-1 bg-slate-800 rounded-full overflow-hidden">
                                                <div
                                                    className="h-full bg-red-500"
                                                    style={{ width: `${(parseInt(step.properties.exploit_impact || "5") * 10)}%` }}
                                                ></div>
                                            </div>
                                        </div>
                                        <div className="flex-1">
                                            <div className="text-[9px] text-slate-600 font-black uppercase mb-1">Risk Score</div>
                                            <div className="text-xs font-mono text-white font-black">
                                                {((parseInt(step.properties.exploit_impact || "5") / parseInt(step.properties.exploit_complexity || "5")) * 10).toFixed(1)}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-12">
                <div className="p-6 bg-slate-900/30 border border-slate-800 rounded-3xl flex items-center gap-6">
                    <div className="p-4 bg-amber-500/10 rounded-2xl text-amber-500">
                        <AlertTriangle size={32} />
                    </div>
                    <div>
                        <h4 className="text-sm font-black text-white uppercase">{isEn ? 'Path Criticality' : 'Criticité du Chemin'}</h4>
                        <p className="text-xs text-slate-500 font-bold mt-1">
                            {isEn ? 'Identified route uses highly effective service pivots with known exploits.' : 'La route utilise des pivots hautement efficaces avec des exploits connus.'}
                        </p>
                    </div>
                </div>
                <div className="p-6 bg-slate-900/30 border border-slate-800 rounded-3xl flex items-center gap-6">
                    <div className="p-4 bg-indigo-500/10 rounded-2xl text-indigo-500">
                        <Terminal size={32} />
                    </div>
                    <div>
                        <h4 className="text-sm font-black text-white uppercase">{isEn ? 'Remediation Priority' : 'Priorité de Remédiation'}</h4>
                        <p className="text-xs text-slate-500 font-bold mt-1">
                            {isEn ? 'Vulnerabilities at Stage 1 and 2 must be patched immediately to break the chain.' : 'Les vulnérabilités aux étapes 1 et 2 doivent être corrigées pour briser la chaîne.'}
                        </p>
                    </div>
                </div>
            </div>
        </div>
    );
};
