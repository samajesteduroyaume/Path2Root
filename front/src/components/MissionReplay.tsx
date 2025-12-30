import React, { useState, useEffect } from 'react';
import { Play, Pause, RotateCcw, ChevronRight, ChevronLeft, Clock, Zap, Target } from 'lucide-react';

interface MissionStep {
    timestamp: number;
    title: String;
    status: String;
}

interface Props {
    logs: MissionStep[];
    onStepSelect?: (step: MissionStep) => void;
}

export const MissionReplay: React.FC<Props> = ({ logs, onStepSelect }) => {
    const [currentIndex, setCurrentIndex] = useState(0);
    const [isPlaying, setIsPlaying] = useState(false);

    useEffect(() => {
        let timer: any;
        if (isPlaying && currentIndex < logs.length - 1) {
            timer = setTimeout(() => {
                setCurrentIndex(prev => prev + 1);
            }, 1000);
        } else {
            setIsPlaying(false);
        }
        return () => clearTimeout(timer);
    }, [isPlaying, currentIndex, logs.length]);

    const handleSelect = (index: number) => {
        setCurrentIndex(index);
        if (onStepSelect) onStepSelect(logs[index]);
    };

    if (!logs || logs.length === 0) return null;

    return (
        <div className="flex flex-col h-full bg-slate-950/50 rounded-3xl border border-slate-800/50 backdrop-blur-xl overflow-hidden scale-in">
            {/* Header / Controls */}
            <div className="p-6 border-b border-slate-800/50 flex items-center justify-between bg-slate-900/20">
                <div className="flex items-center gap-3">
                    <div className="p-2 bg-indigo-500/10 rounded-xl">
                        <Zap size={20} className="text-indigo-400" />
                    </div>
                    <div>
                        <h2 className="text-lg font-black text-white tracking-tight">MISSION REPLAY</h2>
                        <p className="text-[10px] text-slate-500 font-bold uppercase tracking-widest">Temporal Analysis Mode</p>
                    </div>
                </div>

                <div className="flex items-center gap-2 bg-slate-900/50 p-1.5 rounded-2xl border border-slate-800">
                    <button
                        onClick={() => setCurrentIndex(0)}
                        className="p-2 hover:bg-slate-800 text-slate-400 hover:text-white rounded-xl transition-all"
                    >
                        <RotateCcw size={18} />
                    </button>
                    <button
                        onClick={() => setIsPlaying(!isPlaying)}
                        className={`p-3 rounded-xl transition-all ${isPlaying ? 'bg-amber-500 text-black' : 'bg-indigo-600 text-white hover:bg-indigo-500'}`}
                    >
                        {isPlaying ? <Pause size={20} fill="currentColor" /> : <Play size={20} fill="currentColor" />}
                    </button>
                    <div className="px-4 py-2 text-xs font-black text-slate-300 border-l border-slate-800 ml-2">
                        {currentIndex + 1} / {logs.length}
                    </div>
                </div>
            </div>

            {/* Timeline View */}
            <div className="flex-1 overflow-y-auto p-4 space-y-3 custom-scrollbar">
                {logs.map((log, idx) => (
                    <div
                        key={idx}
                        onClick={() => handleSelect(idx)}
                        className={`group relative p-4 rounded-2xl border transition-all cursor-pointer ${idx === currentIndex
                                ? 'bg-indigo-500/10 border-indigo-500/50 neon-glow-blue'
                                : idx < currentIndex
                                    ? 'bg-slate-900/30 border-slate-800/50 opacity-60'
                                    : 'bg-slate-900/10 border-slate-900/50 opacity-30 hover:opacity-100 hover:bg-slate-900/20'
                            }`}
                    >
                        <div className="flex items-center gap-4">
                            <div className={`p-2 rounded-lg ${idx === currentIndex ? 'bg-indigo-500 text-white' : 'bg-slate-800 text-slate-500'
                                }`}>
                                <Clock size={14} />
                            </div>
                            <div className="flex-1">
                                <div className="flex items-center justify-between mb-1">
                                    <span className="text-xs font-black text-white">{log.title}</span>
                                    <span className="text-[9px] font-bold text-slate-500">
                                        {new Date(log.timestamp * 1000).toLocaleTimeString()}
                                    </span>
                                </div>
                                <div className="flex items-center gap-2">
                                    <span className={`text-[9px] font-black px-1.5 py-0.5 rounded uppercase ${log.status === 'Success' ? 'bg-emerald-500/10 text-emerald-400' : 'bg-amber-500/10 text-amber-400'
                                        }`}>
                                        {log.status}
                                    </span>
                                    {idx === currentIndex && (
                                        <div className="h-1 flex-1 bg-indigo-500/20 rounded-full overflow-hidden">
                                            <div className="h-full bg-indigo-500 transition-all duration-1000" style={{ width: '100%' }}></div>
                                        </div>
                                    )}
                                </div>
                            </div>
                            <ChevronRight size={16} className={`transition-all ${idx === currentIndex ? 'text-indigo-400 translate-x-0' : 'text-slate-700 opacity-0 -translate-x-2 group-hover:opacity-100 group-hover:translate-x-0'}`} />
                        </div>
                    </div>
                ))}
            </div>

            {/* Footer Status */}
            <div className="p-4 bg-slate-900/40 border-t border-slate-800/50">
                <div className="flex items-center justify-between text-[10px] font-bold text-slate-500 uppercase tracking-widest">
                    <div className="flex items-center gap-2">
                        <div className={`w-2 h-2 rounded-full ${isPlaying ? 'bg-emerald-500 animate-pulse' : 'bg-slate-700'}`}></div>
                        {isPlaying ? 'Replay Active' : 'Standby'}
                    </div>
                    <div>Step {(currentIndex + 1).toString().padStart(2, '0')}</div>
                </div>
            </div>
        </div>
    );
};
