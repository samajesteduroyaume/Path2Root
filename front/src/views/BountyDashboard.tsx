import React from 'react';
import { Trophy, TrendingUp, AlertTriangle, CheckCircle2, Wallet, Rocket } from 'lucide-react';

interface Mission {
    id: string;
    target: string;
    bounty_earned: number;
    status: string;
}

export const BountyDashboard: React.FC<{ missions?: Mission[] }> = ({ missions = [] }) => {
    const totalEarned = missions.filter(m => m.status === 'Paid').reduce((acc, b) => acc + b.bounty_earned, 0);
    const pending = missions.filter(m => m.status !== 'Paid').reduce((acc, b) => acc + b.bounty_earned, 0);

    return (
        <div className="p-8 space-y-8 bg-slate-950 min-h-full">
            <div className="flex justify-between items-end">
                <div>
                    <h1 className="text-3xl font-black text-white flex items-center gap-3">
                        <Trophy className="text-amber-500 shadow-amber-500/50" size={32} />
                        Bounty Command Center
                    </h1>
                    <p className="text-slate-500 font-bold uppercase text-xs mt-1 tracking-widest">
                        Track your offensive gains and critical discoveries
                    </p>
                </div>
                <div className="flex gap-4">
                    <div className="p-4 bg-slate-900 border border-slate-800 rounded-2xl flex items-center gap-4 bounty-card">
                        <div className="w-10 h-10 bg-green-500/20 rounded-xl flex items-center justify-center text-green-500">
                            <Wallet size={24} />
                        </div>
                        <div>
                            <div className="text-[10px] text-slate-500 font-bold uppercase">Total Wallet</div>
                            <div className="text-xl font-black text-white">${totalEarned.toLocaleString()}</div>
                        </div>
                    </div>
                    <div className="p-4 bg-slate-900 border border-slate-800 rounded-2xl flex items-center gap-4">
                        <div className="w-10 h-10 bg-amber-500/20 rounded-xl flex items-center justify-center text-amber-500">
                            <TrendingUp size={24} />
                        </div>
                        <div>
                            <div className="text-[10px] text-slate-500 font-bold uppercase">Pending Payouts</div>
                            <div className="text-xl font-black text-white">${pending.toLocaleString()}</div>
                        </div>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2 space-y-4">
                    <label className="text-[10px] font-bold uppercase text-slate-500 tracking-widest block px-1">Active Bounty Feed</label>
                    <div className="space-y-3">
                        {missions.length === 0 ? (
                            <div className="p-10 border-2 border-dashed border-slate-800 rounded-3xl text-center">
                                <Rocket className="mx-auto text-slate-700 mb-4" size={48} />
                                <p className="text-slate-500 font-bold uppercase text-xs tracking-tighter">No active missions. Start a scan to earn bounties.</p>
                            </div>
                        ) : missions.map(m => (
                            <div key={m.id} className={`p-5 bg-slate-900 border border-slate-800 rounded-2xl flex items-center justify-between group hover:border-indigo-500/50 transition-all ${m.bounty_earned > 2000 ? 'critical-card' : ''}`}>
                                <div className="flex items-center gap-4">
                                    <div className={`p-3 rounded-xl ${m.bounty_earned > 2000 ? 'bg-red-500/10 text-red-500' : 'bg-blue-500/10 text-blue-500'}`}>
                                        <AlertTriangle size={20} />
                                    </div>
                                    <div>
                                        <div className="text-xs font-black text-white group-hover:text-indigo-400 transition-colors uppercase">{m.target}</div>
                                        <div className="text-[10px] text-slate-500 font-medium">Mission #{m.id.substring(0, 8)} • {m.bounty_earned > 2000 ? 'High' : 'Standard'} Priority</div>
                                    </div>
                                </div>
                                <div className="flex items-center gap-6">
                                    <div className="text-right">
                                        <div className="text-sm font-black text-white">${m.bounty_earned.toLocaleString()}</div>
                                        <div className={`text-[9px] font-bold uppercase ${m.status === 'Paid' ? 'text-green-500' : 'text-slate-500'}`}>{m.status}</div>
                                    </div>
                                    <div className={`w-8 h-8 rounded-full flex items-center justify-center ${m.status === 'Paid' ? 'bg-green-500/20 text-green-500' : 'bg-slate-800 text-slate-600'}`}>
                                        <CheckCircle2 size={16} />
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="space-y-6">
                    <div className="p-6 bg-indigo-600 rounded-3xl text-white relative overflow-hidden shadow-2xl shadow-indigo-500/20">
                        <div className="absolute top-0 right-0 opacity-10">
                            <Trophy size={120} />
                        </div>
                        <h3 className="text-lg font-black leading-tight mb-2">Elite Hunter Program</h3>
                        <p className="text-indigo-100 text-xs font-medium opacity-80 mb-6">Your performance is being monitored. High reward targets are automatically prioritized in the attack graph.</p>
                        <button className="w-full py-3 bg-white text-indigo-600 rounded-xl font-bold text-xs hover:bg-indigo-50 transition-colors shadow-lg">View Leaderboard</button>
                    </div>

                    <div className="p-6 bg-slate-900 border border-slate-800 rounded-3xl space-y-4">
                        <h3 className="text-sm font-black text-white uppercase tracking-tighter">Bounty Statistics</h3>
                        <div className="space-y-4">
                            <BreakdownRow label="Critical Path Discoveries" value={missions.filter(m => m.bounty_earned > 5000).length * 10 || 15} color="bg-red-500" />
                            <BreakdownRow label="Asset Fingerprinting" value={45} color="bg-cyan-500" />
                            <BreakdownRow label="Vulnerability Coverage" value={missions.length ? 75 : 0} color="bg-amber-500" />
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

const BreakdownRow: React.FC<{ label: string, value: number, color: string }> = ({ label, value, color }) => (
    <div className="space-y-1">
        <div className="flex justify-between text-[10px] font-bold text-white mb-2">
            <span className="text-slate-400">{label}</span>
            <span className="text-white">{value}%</span>
        </div>
        <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
            <div className={`h-full ${color} shadow-[0_0_10px_rgba(0,0,0,0.5)]`} style={{ width: `${value}%` }}></div>
        </div>
    </div>
);
