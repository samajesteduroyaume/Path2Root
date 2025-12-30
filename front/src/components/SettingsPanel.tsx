import React, { useState, useEffect } from 'react';
import { Settings, Save, Bell, CheckCircle, AlertCircle, X, ExternalLink } from 'lucide-react';
import axios from 'axios';

interface Props {
    isOpen: boolean;
    onClose: () => void;
    webhookUrl: string;
    setWebhookUrl: (url: string) => void;
    lang: string;
}

export const SettingsPanel: React.FC<Props> = ({ isOpen, onClose, webhookUrl, setWebhookUrl, lang }) => {
    const isEn = lang === 'en';
    const [urlInput, setUrlInput] = useState(webhookUrl);
    const [isTesting, setIsTesting] = useState(false);
    const [testStatus, setTestStatus] = useState<'idle' | 'success' | 'error'>('idle');

    useEffect(() => {
        setUrlInput(webhookUrl);
    }, [webhookUrl]);

    const handleSave = () => {
        setWebhookUrl(urlInput);
        localStorage.setItem('path2root_webhook', urlInput);
    };

    const handleTest = async () => {
        if (!urlInput) return;
        setIsTesting(true);
        setTestStatus('idle');
        try {
            await axios.post('/api/settings/webhook/test', { webhook_url: urlInput });
            setTestStatus('success');
            setTimeout(() => setTestStatus('idle'), 3000);
        } catch (err) {
            console.error(err);
            setTestStatus('error');
        } finally {
            setIsTesting(false);
        }
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-fade-in">
            <div className="bg-slate-900 border border-slate-700 w-full max-w-lg rounded-2xl overflow-hidden shadow-2xl">
                <div className="p-6 border-b border-slate-800 flex justify-between items-center bg-slate-950">
                    <h2 className="text-xl font-black text-white flex items-center gap-3">
                        <Settings className="text-indigo-500" />
                        {isEn ? 'System Configuration' : 'Configuration Système'}
                    </h2>
                    <button onClick={onClose} className="text-slate-500 hover:text-white transition-colors">
                        <X size={24} />
                    </button>
                </div>

                <div className="p-6 space-y-6">
                    <div className="space-y-4">
                        <h3 className="text-sm font-bold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                            <Bell size={14} /> Webhook Notifications
                        </h3>
                        <div className="bg-slate-800/50 p-4 rounded-xl border border-slate-700">
                            <label className="block text-xs font-bold text-slate-400 mb-2">
                                Discord / Slack Webhook URL
                            </label>
                            <div className="flex gap-2">
                                <input
                                    type="text"
                                    value={urlInput}
                                    onChange={(e) => setUrlInput(e.target.value)}
                                    placeholder="https://discord.com/api/webhooks/..."
                                    className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500 transition-colors"
                                />
                            </div>
                            <div className="mt-3 flex justify-between items-center">
                                <p className="text-[10px] text-slate-500">
                                    {isEn ? 'Supports Discord Embeds & Slack Incoming Webhooks.' : 'Supporte Discord Embeds & Slack Incoming Webhooks.'}
                                </p>
                                <button
                                    onClick={handleTest}
                                    disabled={!urlInput || isTesting}
                                    className={`px-3 py-1 rounded-lg text-xs font-bold uppercase transition-all flex items-center gap-2
                     ${testStatus === 'success' ? 'bg-green-500/20 text-green-400' :
                                            testStatus === 'error' ? 'bg-red-500/20 text-red-400' :
                                                'bg-indigo-600 hover:bg-indigo-500 text-white shadow-lg shadow-indigo-500/20'}`}
                                >
                                    {isTesting ? 'Sending...' : testStatus === 'success' ? 'Sent!' : testStatus === 'error' ? 'Failed' : isEn ? 'Test Connectivity' : 'Tester Connexion'}
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="p-4 border-t border-slate-800 bg-slate-950 flex justify-end gap-3">
                    <button
                        onClick={onClose}
                        className="px-4 py-2 rounded-xl text-slate-400 font-bold hover:text-white hover:bg-slate-800 transition-all text-sm"
                    >
                        {isEn ? 'Cancel' : 'Annuler'}
                    </button>
                    <button
                        onClick={() => { handleSave(); onClose(); }}
                        className="px-6 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold shadow-lg shadow-indigo-500/20 transition-all flex items-center gap-2 text-sm"
                    >
                        <Save size={16} />
                        {isEn ? 'Save Changes' : 'Enregistrer'}
                    </button>
                </div>
            </div>
        </div>
    );
};
