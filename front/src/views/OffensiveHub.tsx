import React, { useState } from 'react';
import { Target, Zap, Terminal, ShieldAlert, Play, Trash2, Cpu, Activity, ChevronRight, Copy, CheckCircle, AlertCircle } from 'lucide-react';
import axios from 'axios';

interface Operation {
    id: string;
    command: string;
    output: string;
    exit_code: number;
    timestamp: number;
    success: boolean;
}

interface Props {
    lang: string;
    initialCommand?: string;
}

export const OffensiveHub: React.FC<Props> = ({ lang, initialCommand = "" }) => {
    const isEn = lang === 'en';
    const [command, setCommand] = useState(initialCommand);
    const [history, setHistory] = useState<Operation[]>([]);
    const [isRunning, setIsRunning] = useState(false);
    const [lastResult, setLastResult] = useState<Operation | null>(null);

    const executeCommand = async () => {
        if (!command.trim()) return;
        setIsRunning(true);
        try {
            const resp = await axios.post('/api/exploit/run', { command });
            const result = resp.data;
            setLastResult(result);
            setHistory(prev => [result, ...prev]);
        } catch (err: any) {
            console.error("Exploit execution failed", err);
            const errorOp: Operation = {
                id: `error-${Date.now()}`,
                command,
                output: err.response?.data?.error || err.message || "Unknown execution failure",
                exit_code: -1,
                timestamp: Date.now() / 1000,
                success: false
            };
            setHistory(prev => [errorOp, ...prev]);
        } finally {
            setIsRunning(false);
        }
    };

    const clearHistory = () => setHistory([]);

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
    };

    return (
        <div className="p-8 space-y-8 bg-slate-950 min-h-full">
            <div className="flex justify-between items-end">
                <div>
                    <h1 className="text-3xl font-black text-white flex items-center gap-3 uppercase tracking-tighter">
                        <Target className="text-rose-500" size={32} />
                        {isEn ? 'Offensive Operations Hub' : 'Hub d\'Opérations Offensives'}
                    </h1>
                    <p className="text-slate-500 font-bold uppercase text-[10px] mt-1 tracking-[0.3em]">
                        {isEn ? 'Tactical Exploit Execution & Control' : 'Exécution & Contrôle d\'Exploits Tactiques'}
                    </p>
                </div>
                <div className="flex gap-4">
                    <div className="flex items-center gap-2 px-4 py-2 bg-slate-900 border border-slate-800 rounded-2xl group transition-all">
                        <Activity size={16} className="text-emerald-500 animate-pulse" />
                        <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">System Status: <span className="text-emerald-400">READY</span></span>
                    </div>
                </div>
            </div>

            {/* Execution Console */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <div className="lg:col-span-2 space-y-6">
                    <div className="bg-slate-900/50 border border-slate-800 rounded-[32px] p-8 glass-panel space-y-6">
                        <div className="flex justify-between items-center">
                            <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest flex items-center gap-2">
                                <Terminal size={14} className="text-rose-500" />
                                {isEn ? 'Manual Payload Entry' : 'Saisie Manuelle du Payload'}
                            </label>
                            {lastResult && (
                                <div className={`px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-tighter flex items-center gap-2 ${lastResult.success ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'}`}>
                                    {lastResult.success ? <CheckCircle size={10} /> : <AlertCircle size={10} />}
                                    {lastResult.success ? 'Success' : 'Failed'} [Code: {lastResult.exit_code}]
                                </div>
                            )}
                        </div>

                        <div className="relative group">
                            <textarea
                                value={command}
                                onChange={(e) => setCommand(e.target.value)}
                                placeholder={isEn ? "Enter offensive command (curl, nmap -sV, etc.)..." : "Saisissez la commande offensive (curl, nmap -sV, etc.)..."}
                                className="w-full bg-black/60 border border-white/5 rounded-2xl p-6 text-sm font-mono text-emerald-400 focus:outline-none focus:border-rose-500/50 transition-all min-h-[120px] shadow-inner"
                            />
                            <div className="absolute top-4 right-4 flex gap-2">
                                <button
                                    onClick={() => setCommand("")}
                                    className="p-2 bg-slate-800/50 hover:bg-slate-700 text-slate-400 hover:text-white rounded-lg transition-all"
                                >
                                    <Trash2 size={14} />
                                </button>
                            </div>
                        </div>

                        <div className="flex justify-between items-center gap-4">
                            <p className="text-[10px] text-slate-500 italic max-w-md">
                                {isEn
                                    ? "Execution is direct. Ensure you have authorized access to the target system before launching the probe."
                                    : "L'exécution est directe. Assurez-vous d'avoir un accès autorisé au système cible avant de lancer la sonde."}
                            </p>
                            <button
                                onClick={executeCommand}
                                disabled={isRunning || !command.trim()}
                                className={`px-8 py-4 rounded-2xl flex items-center gap-3 text-xs font-black uppercase tracking-widest transition-all shadow-xl ${isRunning || !command.trim() ? 'bg-slate-800 text-slate-500' : 'bg-rose-600 hover:bg-rose-500 text-white shadow-rose-950/40 hover:-translate-y-1'}`}
                            >
                                {isRunning ? <Cpu className="animate-spin" size={18} /> : <Play size={18} />}
                                {isEn ? 'EMIT PAYLOAD' : 'ÉMETTRE PAYLOAD'}
                            </button>
                        </div>
                    </div>

                    {/* Output Terminal */}
                    {lastResult && (
                        <div className="bg-black/80 border border-slate-800 rounded-[32px] overflow-hidden flex flex-col h-[400px] shadow-2xl">
                            <div className="px-6 py-3 bg-slate-900/80 border-b border-slate-800 flex justify-between items-center">
                                <div className="flex items-center gap-2">
                                    <div className="flex gap-1.5">
                                        <div className="w-2.5 h-2.5 rounded-full bg-rose-500/20 border border-rose-500/40"></div>
                                        <div className="w-2.5 h-2.5 rounded-full bg-amber-500/20 border border-amber-500/40"></div>
                                        <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/20 border border-emerald-500/40"></div>
                                    </div>
                                    <span className="text-[10px] font-black text-slate-500 uppercase ml-4 tracking-widest">{isEn ? 'Raw Terminal Output' : 'Sortie Terminal Brute'}</span>
                                </div>
                                <button
                                    onClick={() => copyToClipboard(lastResult.output)}
                                    className="text-[10px] font-black text-slate-500 hover:text-white flex items-center gap-2 transition-colors"
                                >
                                    <Copy size={12} /> {isEn ? 'COPY OUTPUT' : 'COPIER LA SORTIE'}
                                </button>
                            </div>
                            <div className="flex-1 p-6 font-mono text-xs text-slate-300 overflow-y-auto whitespace-pre-wrap custom-scrollbar">
                                <span className="text-emerald-500 mr-2">$</span>
                                <span className="text-slate-400">{lastResult.command}</span>
                                <div className="mt-4 border-l-2 border-slate-800 pl-4">
                                    {lastResult.output}
                                </div>
                            </div>
                        </div>
                    )}
                </div>

                {/* History Sidebar */}
                <div className="space-y-6">
                    <div className="flex items-center justify-between px-2">
                        <h2 className="text-sm font-black text-white uppercase tracking-widest flex items-center gap-2">
                            <ShieldAlert size={16} className="text-rose-500" />
                            {isEn ? 'Mission Log' : 'Journal de Mission'}
                        </h2>
                        <button
                            onClick={clearHistory}
                            className="text-[10px] font-bold text-slate-500 hover:text-rose-400 transition-colors"
                        >
                            CLEAR
                        </button>
                    </div>

                    <div className="space-y-4 max-h-[700px] overflow-y-auto pr-2 custom-scrollbar">
                        {history.length === 0 ? (
                            <div className="p-8 text-center bg-slate-900/20 rounded-3xl border border-dashed border-slate-800">
                                <Zap size={32} className="mx-auto text-slate-800 mb-3" />
                                <p className="text-[10px] font-bold text-slate-600 uppercase tracking-widest">No operations recorded.</p>
                            </div>
                        ) : (
                            history.map(op => (
                                <div
                                    key={op.id}
                                    onClick={() => setLastResult(op)}
                                    className={`p-4 bg-slate-900 border rounded-2xl cursor-pointer transition-all hover:border-rose-500/30 ${lastResult?.id === op.id ? 'border-rose-500/50 ring-1 ring-rose-500/20' : 'border-slate-800'}`}
                                >
                                    <div className="flex justify-between items-start mb-2">
                                        <div className={`w-2 h-2 rounded-full mt-1.5 ${op.success ? 'bg-emerald-500' : 'bg-rose-500'}`}></div>
                                        <span className="text-[10px] font-mono text-slate-600">{new Date(op.timestamp * 1000).toLocaleTimeString()}</span>
                                    </div>
                                    <p className="text-[11px] font-mono text-slate-400 line-clamp-2 mb-2 break-all">{op.command}</p>
                                    <div className="flex items-center justify-between">
                                        <span className={`text-[9px] font-black uppercase ${op.success ? 'text-emerald-500' : 'text-rose-500'}`}>
                                            {op.success ? 'Completed' : 'Error'}
                                        </span>
                                        <ChevronRight size={14} className="text-slate-700" />
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
};
