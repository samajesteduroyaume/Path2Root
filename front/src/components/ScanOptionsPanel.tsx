import React from 'react';
import { Settings, Zap, Target, Eye, Ghost, Globe, Shield } from 'lucide-react';

interface ScanOptionsProps {
    profile: string;
    customPorts: string;
    timing: number;
    enableUdp: boolean;
    enableShodan: boolean;
    enableVirusTotal: boolean;
    enableCensys: boolean;
    enableAlienVault: boolean;
    onProfileChange: (profile: string) => void;
    onCustomPortsChange: (ports: string) => void;
    onTimingChange: (timing: number) => void;
    onEnableUdpChange: (enabled: boolean) => void;
    onEnableShodanChange: (enabled: boolean) => void;
    onEnableVirusTotalChange: (enabled: boolean) => void;
    onEnableCensysChange: (enabled: boolean) => void;
    onEnableAlienVaultChange: (enabled: boolean) => void;
    autoExploit: boolean;
    onAutoExploitChange: (enabled: boolean) => void;
    lang: string;
}

export const ScanOptionsPanel: React.FC<ScanOptionsProps> = ({
    profile,
    customPorts,
    timing,
    enableUdp,
    enableShodan,
    enableVirusTotal,
    enableCensys,
    enableAlienVault,
    autoExploit,
    onProfileChange,
    onCustomPortsChange,
    onTimingChange,
    onEnableUdpChange,
    onEnableShodanChange,
    onEnableVirusTotalChange,
    onEnableCensysChange,
    onEnableAlienVaultChange,
    onAutoExploitChange,
    lang
}) => {
    const isEn = lang === 'en';

    return (
        <div className="space-y-4">
            <label className="text-xs font-semibold uppercase tracking-wider text-slate-500 flex items-center gap-2">
                <Settings size={14} />
                {isEn ? 'Scan Options' : 'Options de Scan'}
            </label>

            {/* Profile Selector */}
            <div className="space-y-2">
                <label className="text-[10px] font-bold text-slate-400">{isEn ? 'Profile' : 'Profil'}</label>
                <div className="grid grid-cols-2 gap-2">
                    {/* Fast Profile */}
                    <button
                        onClick={() => onProfileChange('fast')}
                        className={`p-3 rounded-xl border ${profile === 'fast'
                            ? 'bg-indigo-600 border-indigo-500 shadow-lg shadow-indigo-500/30'
                            : 'bg-slate-900 border-slate-800 hover:border-slate-700'
                            }`}
                    >
                        <div className="flex flex-col items-center gap-1">
                            <Zap size={16} className={profile === 'fast' ? 'text-white' : 'text-green-400'} />
                            <span className={`text-[10px] font-bold ${profile === 'fast' ? 'text-white' : 'text-slate-400'}`}>
                                {isEn ? 'Fast' : 'Rapide'}
                            </span>
                            <span className="text-[8px] text-slate-500">Top 100 ports</span>
                        </div>
                    </button>

                    {/* Normal Profile */}
                    <button
                        onClick={() => onProfileChange('normal')}
                        className={`p-3 rounded-xl border ${profile === 'normal'
                            ? 'bg-indigo-600 border-indigo-500 shadow-lg shadow-indigo-500/30'
                            : 'bg-slate-900 border-slate-800 hover:border-slate-700'
                            }`}
                    >
                        <div className="flex flex-col items-center gap-1">
                            <Target size={16} className={profile === 'normal' ? 'text-white' : 'text-blue-400'} />
                            <span className={`text-[10px] font-bold ${profile === 'normal' ? 'text-white' : 'text-slate-400'}`}>
                                Normal
                            </span>
                            <span className="text-[8px] text-slate-500">Top 1000 ports</span>
                        </div>
                    </button>

                    {/* Deep Profile */}
                    <button
                        onClick={() => onProfileChange('deep')}
                        className={`p-3 rounded-xl border ${profile === 'deep'
                            ? 'bg-indigo-600 border-indigo-500 shadow-lg shadow-indigo-500/30'
                            : 'bg-slate-900 border-slate-800 hover:border-slate-700'
                            }`}
                    >
                        <div className="flex flex-col items-center gap-1">
                            <Eye size={16} className={profile === 'deep' ? 'text-white' : 'text-purple-400'} />
                            <span className={`text-[10px] font-bold ${profile === 'deep' ? 'text-white' : 'text-slate-400'}`}>
                                {isEn ? 'Deep' : 'Profond'}
                            </span>
                            <span className="text-[8px] text-slate-500">{isEn ? 'All 65535 ports' : 'Tous les ports'}</span>
                        </div>
                    </button>

                    {/* Stealth Profile */}
                    <button
                        onClick={() => onProfileChange('stealth')}
                        className={`p-3 rounded-xl border ${profile === 'stealth'
                            ? 'bg-indigo-600 border-indigo-500 shadow-lg shadow-indigo-500/30'
                            : 'bg-slate-900 border-slate-800 hover:border-slate-700'
                            }`}
                    >
                        <div className="flex flex-col items-center gap-1">
                            <Ghost size={16} className={profile === 'stealth' ? 'text-white' : 'text-slate-400'} />
                            <span className={`text-[10px] font-bold ${profile === 'stealth' ? 'text-white' : 'text-slate-400'}`}>
                                {isEn ? 'Stealth' : 'Furtif'}
                            </span>
                            <span className="text-[8px] text-slate-500">{isEn ? 'IDS evasion' : 'Évite les IDS'}</span>
                        </div>
                    </button>
                </div>
            </div>

            {/* Custom Ports */}
            <div className="space-y-2">
                <label className="text-[10px] font-bold text-slate-400">
                    {isEn ? 'Custom Ports (optional)' : 'Ports personnalisés (optionnel)'}
                </label>
                <input
                    type="text"
                    placeholder="80,443,8000-9000"
                    value={customPorts}
                    onChange={(e) => onCustomPortsChange(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-800 rounded-xl py-2 px-3 text-xs focus:ring-2 focus:ring-blue-500 outline-none transition-all"
                />
                <p className="text-[8px] text-slate-600">{isEn ? 'Leave empty to use profile defaults' : 'Laisser vide pour utiliser le profil par défaut'}</p>
            </div>

            {/* UDP Toggle */}
            <div className="flex items-center justify-between p-3 bg-slate-900/50 border border-slate-800 rounded-xl">
                <div>
                    <label className="text-[10px] font-bold text-slate-400">{isEn ? 'UDP Scan' : 'Scan UDP'}</label>
                    <p className="text-[8px] text-slate-600">{isEn ? 'DNS, SNMP, NTP (slower)' : 'DNS, SNMP, NTP (plus lent)'}</p>
                </div>
                <input
                    type="checkbox"
                    checked={enableUdp}
                    onChange={(e) => onEnableUdpChange(e.target.checked)}
                    className="w-4 h-4 text-blue-600 bg-slate-800 border-slate-700 rounded focus:ring-blue-500 focus:ring-2"
                />
            </div>

            {/* Shodan Toggle */}
            <div className="flex items-center justify-between p-3 bg-slate-900/50 border border-slate-800 rounded-xl">
                <div>
                    <label className="text-[10px] font-bold text-slate-400 flex items-center gap-2">
                        <Globe size={10} />
                        {isEn ? 'Shodan Enrichment' : 'Enrichissement Shodan'}
                    </label>
                    <p className="text-[8px] text-slate-600">{isEn ? 'Threat intel from Shodan.io' : 'Renseignement Shodan.io'}</p>
                </div>
                <input
                    type="checkbox"
                    checked={enableShodan}
                    onChange={(e) => onEnableShodanChange(e.target.checked)}
                    className="w-4 h-4 text-blue-600 bg-slate-800 border-slate-700 rounded focus:ring-blue-500 focus:ring-2"
                />
            </div>

            {/* VirusTotal Toggle */}
            <div className="flex items-center justify-between p-3 bg-slate-900/50 border border-slate-800 rounded-xl">
                <div>
                    <label className="text-[10px] font-bold text-slate-400 flex items-center gap-2">
                        <Shield size={10} />
                        {isEn ? 'VirusTotal Reputation' : 'Réputation VirusTotal'}
                    </label>
                    <p className="text-[8px] text-slate-600">{isEn ? 'Malware & reputation check' : 'Vérification malware & réputation'}</p>
                </div>
                <input
                    type="checkbox"
                    checked={enableVirusTotal}
                    onChange={(e) => onEnableVirusTotalChange(e.target.checked)}
                    className="w-4 h-4 text-blue-600 bg-slate-800 border-slate-700 rounded focus:ring-blue-500 focus:ring-2"
                />
            </div>

            {/* Censys Toggle */}
            <div className="flex items-center justify-between p-3 bg-slate-900/50 border border-slate-800 rounded-xl">
                <div>
                    <label className="text-[10px] font-bold text-slate-400 flex items-center gap-2">
                        <Globe size={10} />
                        {isEn ? 'Censys Enrichment' : 'Enrichissement Censys'}
                    </label>
                    <p className="text-[8px] text-slate-600">{isEn ? 'Host data from Censys.io' : 'Données hôte via Censys.io'}</p>
                </div>
                <input
                    type="checkbox"
                    checked={enableCensys}
                    onChange={(e) => onEnableCensysChange(e.target.checked)}
                    className="w-4 h-4 text-orange-600 bg-slate-800 border-slate-700 rounded focus:ring-orange-500 focus:ring-2"
                />
            </div>

            {/* AlienVault Toggle */}
            <div className="flex items-center justify-between p-3 bg-slate-900/50 border border-slate-800 rounded-xl">
                <div>
                    <label className="text-[10px] font-bold text-slate-400 flex items-center gap-2">
                        <Shield size={10} />
                        {isEn ? 'OTX Threat Intel' : 'Threat Intel OTX'}
                    </label>
                    <p className="text-[8px] text-slate-600">{isEn ? 'Threat pulses from AlienVault' : 'Flux de menaces via AlienVault'}</p>
                </div>
                <input
                    type="checkbox"
                    checked={enableAlienVault}
                    onChange={(e) => onEnableAlienVaultChange(e.target.checked)}
                    className="w-4 h-4 text-purple-600 bg-slate-800 border-slate-700 rounded focus:ring-purple-500 focus:ring-2"
                />
            </div>

            {/* Autonomous Toggle */}
            <div className="flex items-center justify-between p-3 bg-rose-950/20 border border-rose-500/20 rounded-xl shadow-lg shadow-rose-900/10">
                <div>
                    <label className="text-[10px] font-black text-rose-400 flex items-center gap-2">
                        <Zap size={10} className="animate-pulse" />
                        {isEn ? 'AUTONOMOUS MODE' : 'MODE AUTONOME'}
                    </label>
                    <p className="text-[8px] text-rose-600 font-medium">{isEn ? 'Auto-trigger PoCs & Exploits' : 'Déclenche PoCs & Exploits auto'}</p>
                </div>
                <input
                    type="checkbox"
                    checked={autoExploit}
                    onChange={(e) => onAutoExploitChange(e.target.checked)}
                    className="w-4 h-4 text-rose-600 bg-slate-800 border-rose-800 rounded focus:ring-rose-500 focus:ring-2 transition-all cursor-pointer"
                />
            </div>

            {/* Timing Slider */}
            <div className="space-y-2">
                <div className="flex justify-between items-center">
                    <label className="text-[10px] font-bold text-slate-400">
                        {isEn ? 'Speed' : 'Vitesse'}
                    </label>
                    <span className="text-xs font-mono text-blue-400">T{timing}</span>
                </div>
                <input
                    type="range"
                    min="0"
                    max="5"
                    value={timing}
                    onChange={(e) => onTimingChange(parseInt(e.target.value))}
                    className="w-full h-2 bg-slate-800 rounded-lg appearance-none cursor-pointer slider"
                />
                <div className="flex justify-between text-[8px] text-slate-600">
                    <span>{isEn ? 'Slow' : 'Lent'}</span>
                    <span>{isEn ? 'Fast' : 'Rapide'}</span>
                </div>
            </div>

            {/* Profile Description */}
            <div className="p-3 bg-slate-900/50 border border-slate-800 rounded-xl">
                {profile === 'fast' && (
                    <div className="text-[9px] text-slate-400 leading-relaxed">
                        {isEn ? '⚡ Quick reconnaissance (30s-1min). Scans top 100 ports with basic scripts.' : '⚡ Reconnaissance rapide (30s-1min). Scanne les 100 ports principaux avec scripts basiques.'}
                    </div>
                )}
                {profile === 'normal' && (
                    <div className="text-[9px] text-slate-400 leading-relaxed">
                        {isEn ? '🎯 Standard audit. Scans top 1000 ports with full vulnerability detection.' : '🎯 Audit standard. Scanne 1000 ports avec détection complète des vulnérabilités.'}
                    </div>
                )}
                {profile === 'deep' && (
                    <div className="text-[9px] text-slate-400 leading-relaxed">
                        {isEn ? '🔍 Comprehensive pentest (10-30min). Scans all 65535 ports with aggressive detection.' : '🔍 Pentest complet (10-30min). Scanne tous les 65535 ports avec détection aggressive.'}
                    </div>
                )}
                {profile === 'stealth' && (
                    <div className="text-[9px] text-slate-400 leading-relaxed">
                        {isEn ? '🥷 IDS/IPS evasion. Slow scan with packet fragmentation and host randomization.' : '🥷 Évite les IDS/IPS. Scan lent avec fragmentation de paquets et randomisation.'}
                    </div>
                )}
            </div>
        </div>
    );
};
