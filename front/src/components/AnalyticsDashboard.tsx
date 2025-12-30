import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { BarChart3, PieChart, TrendingUp, Shield, Activity, Target, Zap, AlertTriangle } from 'lucide-react';

interface Stats {
    total_missions: number;
    total_bounty: number;
    hostname_count: number;
    vulnerability_count: number;
    severity_distribution: Record<string, number>;
}

export const AnalyticsDashboard: React.FC<{ lang: string }> = ({ lang }) => {
    const [stats, setStats] = useState<Stats | null>(null);
    const [loading, setLoading] = useState(true);
    const isEn = lang === 'en';

    useEffect(() => {
        const fetchStats = async () => {
            try {
                const token = localStorage.getItem('path2root_token');
                const headers = token ? { Authorization: `Bearer ${token}` } : {};
                const response = await axios.get('/api/analytics/stats', { headers });
                setStats(response.data);
            } catch (err) {
                console.error("Failed to fetch analytics", err);
            } finally {
                setLoading(false);
            }
        };
        fetchStats();
    }, []);

    if (loading) {
        return (
            <div className="flex-1 flex items-center justify-center bg-[#0d0d0d]">
                <Activity className="animate-spin text-indigo-500" size={32} />
            </div>
        );
    }

    if (!stats) return null;

    const totalVulns = Object.values(stats.severity_distribution).reduce((a, b) => a + b, 0);

    return (
        <div className="flex-1 overflow-y-auto p-8 bg-[#0d0d0d] custom-scrollbar animate-fade-in">
            <div className="max-w-6xl mx-auto space-y-8">
                <div>
                    <h2 className="text-3xl font-black text-white tracking-tighter flex items-center gap-3">
                        <BarChart3 className="text-indigo-500" size={32} />
                        {isEn ? 'Security Analytics' : 'Analytique Sécurité'}
                    </h2>
                    <p className="text-slate-500 text-sm mt-1">
                        {isEn ? 'Comprehensive overview of your infrastructure security posture.' : 'Aperçu complet de la posture de sécurité de votre infrastructure.'}
                    </p>
                </div>

                {/* Big Cards */}
                <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                    <StatCard
                        icon={<Target className="text-blue-400" />}
                        label={isEn ? "Total Targets" : "Cibles Totales"}
                        value={stats.total_missions}
                        color="blue"
                    />
                    <StatCard
                        icon={<Shield className="text-indigo-400" />}
                        label={isEn ? "Hosts Audited" : "Hôtes Audités"}
                        value={stats.hostname_count}
                        color="indigo"
                    />
                    <StatCard
                        icon={<AlertTriangle className="text-rose-400" />}
                        label={isEn ? "Vulnerabilities" : "Vulnérabilités"}
                        value={stats.vulnerability_count}
                        color="rose"
                    />
                    <StatCard
                        icon={<Zap className="text-amber-400" />}
                        label={isEn ? "Bounty Potential" : "Bounty Potentiel"}
                        value={`$${stats.total_bounty.toLocaleString()}`}
                        color="amber"
                    />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                    {/* Severity Distribution */}
                    <div className="glass-panel p-6 rounded-3xl border border-slate-800 bg-slate-950/40">
                        <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-6 flex items-center gap-2">
                            <PieChart size={14} />
                            {isEn ? 'Severity Distribution' : 'Distribution par Sévérité'}
                        </h3>
                        <div className="space-y-4">
                            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(sev => {
                                const count = stats.severity_distribution[sev] || 0;
                                const percent = totalVulns > 0 ? (count / totalVulns) * 100 : 0;
                                const color = sev === 'CRITICAL' ? 'bg-rose-500' :
                                    sev === 'HIGH' ? 'bg-orange-500' :
                                        sev === 'MEDIUM' ? 'bg-amber-500' :
                                            sev === 'LOW' ? 'bg-blue-500' : 'bg-slate-500';

                                return (
                                    <div key={sev} className="space-y-1">
                                        <div className="flex justify-between items-center text-[10px] font-bold">
                                            <span className="text-slate-400">{sev}</span>
                                            <span className="text-white">{count} ({percent.toFixed(1)}%)</span>
                                        </div>
                                        <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                                            <div
                                                className={`h-full ${color} transition-all duration-1000`}
                                                style={{ width: `${percent}%` }}
                                            />
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    </div>

                    {/* Historical Trends placeholder */}
                    <div className="glass-panel p-6 rounded-3xl border border-slate-800 bg-slate-950/40 flex flex-col justify-center items-center text-center">
                        <TrendingUp size={48} className="text-slate-800 mb-4" />
                        <h3 className="text-sm font-bold text-white mb-2">{isEn ? 'Historical Insights' : 'Perspectives Historiques'}</h3>
                        <p className="text-xs text-slate-500 max-w-[240px]">
                            {isEn ? 'Cumulative risk score tracking across all missions.' : 'Suivi du score de risque cumulé sur toutes les missions.'}
                        </p>
                        <div className="mt-6 flex items-baseline gap-2">
                            <span className="text-4xl font-black text-indigo-500">+{Math.round(stats.total_bounty / 1000)}k</span>
                            <span className="text-[10px] font-bold text-slate-600 uppercase">Growth</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

const StatCard = ({ icon, label, value, color }: { icon: React.ReactNode, label: string, value: string | number, color: string }) => (
    <div className={`p-6 rounded-3xl border border-slate-800 bg-slate-950/20 glass-panel hover:border-${color}-500/30 transition-all group`}>
        <div className="p-3 bg-slate-900 w-fit rounded-2xl mb-4 group-hover:scale-110 transition-transform">
            {icon}
        </div>
        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">{label}</p>
        <p className="text-2xl font-black text-white mt-1">{value}</p>
    </div>
);
