import React from 'react';
import { History, Target, Calendar, ArrowRight, Trophy } from 'lucide-react';

export interface MissionSummary {
    id: string;
    target: string;
    status: string;
    bounty_earned: number;
    created_at: number;
}

interface Props {
    missions: MissionSummary[];
    onSelect: (mission: MissionSummary) => void;
    onCompare: (id1: string, id2: string) => void;
    lang: string;
}

export const MissionHistory: React.FC<Props> = ({ missions, onSelect, onCompare, lang }) => {
    const isEn = lang === 'en';
    const [compareMode, setCompareMode] = React.useState(false);
    const [selectedForCompare, setSelectedForCompare] = React.useState<string[]>([]);

    const toggleSelection = (id: string, e: React.MouseEvent) => {
        if (!compareMode) {
            onSelect(missions.find(m => m.id === id)!);
            return;
        }

        e.stopPropagation();
        setSelectedForCompare(prev => {
            if (prev.includes(id)) return prev.filter(i => i !== id);
            if (prev.length >= 2) return [prev[1], id]; // Keep last selected + new one (rolling window)
            return [...prev, id];
        });
    };

    const handleCompare = () => {
        if (selectedForCompare.length === 2) {
            onCompare(selectedForCompare[0], selectedForCompare[1]);
            setCompareMode(false);
            setSelectedForCompare([]);
        }
    };

    if (missions.length === 0) {
        return (
            <div className="p-12 text-center space-y-4">
                <History size={48} className="mx-auto text-slate-800" />
                <p className="text-slate-500 font-bold uppercase text-xs tracking-widest">
                    {isEn ? 'No combat history detected' : 'Aucun historique de combat détecté'}
                </p>
            </div>
        );
    }

    return (
        <div className="space-y-4">
            <div className="flex justify-between items-center">
                <h3 className="text-sm font-black text-white uppercase tracking-tighter flex items-center gap-2">
                    <History size={16} className="text-indigo-400" />
                    {isEn ? 'Operation Archives' : 'Archives des Opérations'}
                </h3>
                <button
                    onClick={() => { setCompareMode(!compareMode); setSelectedForCompare([]); }}
                    className={`text-[10px] font-bold uppercase px-2 py-1 rounded-lg transition-colors ${compareMode ? 'bg-indigo-600 text-white' : 'bg-slate-800 text-slate-400 hover:bg-slate-700'}`}
                >
                    {isEn ? 'Compare' : 'Comparer'}
                </button>
            </div>

            {compareMode && (
                <div className="p-3 bg-indigo-900/20 border border-indigo-500/30 rounded-xl text-center">
                    <p className="text-xs text-indigo-300 font-bold mb-2">
                        {isEn ? `Select 2 scans to compare (${selectedForCompare.length}/2)` : `Sélectionnez 2 scans à comparer (${selectedForCompare.length}/2)`}
                    </p>
                    {selectedForCompare.length === 2 && (
                        <button
                            onClick={handleCompare}
                            className="w-full py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-black text-xs uppercase rounded-lg transition-all shadow-lg shadow-indigo-500/20 animate-pulse"
                        >
                            {isEn ? 'Launch Comparison Analysis' : 'Lancer l\'Analyse Comparative'}
                        </button>
                    )}
                </div>
            )}

            <div className="grid gap-3 max-h-[400px] overflow-y-auto pr-2 custom-scrollbar">
                {missions.map((mission) => {
                    const isSelected = selectedForCompare.includes(mission.id);
                    return (
                        <button
                            key={mission.id}
                            onClick={(e) => toggleSelection(mission.id, e)}
                            className={`group w-full flex items-center justify-between p-4 border rounded-2xl transition-all text-left relative overflow-hidden
                                ${isSelected
                                    ? 'bg-indigo-600/20 border-indigo-500 shadow-lg shadow-indigo-500/10'
                                    : 'bg-slate-900/50 border-slate-800 hover:border-indigo-500/50'
                                }
                                ${compareMode && !isSelected ? 'opacity-60 hover:opacity-100' : ''}
                            `}
                        >
                            {isSelected && <div className="absolute inset-0 border-2 border-indigo-500 rounded-2xl pointer-events-none"></div>}
                            <div className="flex items-center gap-4">
                                <div className={`w-10 h-10 rounded-xl flex items-center justify-center transition-colors 
                                    ${isSelected ? 'bg-indigo-500 text-white' : (mission.bounty_earned > 2000 ? 'bg-red-500/10 text-red-500' : 'bg-indigo-500/10 text-indigo-400')}
                                `}>
                                    {isSelected ? <ArrowRight size={20} /> : <Target size={20} />}
                                </div>
                                <div>
                                    <div className="text-xs font-black text-white uppercase">{mission.target}</div>
                                    <div className="flex items-center gap-3 text-[10px] text-slate-500 mt-1">
                                        <span className="flex items-center gap-1 font-bold">
                                            <Calendar size={10} /> {new Date(Number(mission.created_at || Math.floor(Date.now() / 1000)) * 1000).toLocaleDateString()}
                                        </span>
                                        <span className={`px-2 py-0.5 rounded-md font-bold uppercase ${mission.status === 'Paid' ? 'bg-green-500/10 text-green-400' : 'bg-slate-800 text-slate-400'}`}>
                                            {mission.status}
                                        </span>
                                    </div>
                                </div>
                            </div>
                            <div className="flex items-center gap-3">
                                {mission.bounty_earned > 0 && (
                                    <div className={`text-sm font-black flex items-center gap-1 ${mission.bounty_earned > 2000 ? 'text-red-500' : 'text-amber-500'}`}>
                                        <Trophy size={12} /> ${mission.bounty_earned.toLocaleString()}
                                    </div>
                                )}
                            </div>
                        </button>
                    );
                })}
            </div>
        </div>
    );
};
