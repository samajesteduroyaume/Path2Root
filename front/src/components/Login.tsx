import React, { useState } from 'react';
import { Shield, Lock, User, ArrowRight, Loader2 } from 'lucide-react';
import axios from 'axios';
import { useAuth } from '../context/AuthContext';

export const Login: React.FC<{ onToggle: () => void }> = ({ onToggle }) => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    const { login } = useAuth();

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsLoading(true);
        setError('');
        try {
            const resp = await axios.post('/api/auth/login', { username, password });
            login(resp.data.token, resp.data.role, username);
        } catch (err: any) {
            const errorMsg = typeof err.response?.data === 'object'
                ? (err.response.data.error || err.response.data.message || JSON.stringify(err.response.data))
                : (err.response?.data || 'Login failed. Please check your credentials.');
            setError(errorMsg);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="min-h-screen w-full flex items-center justify-center bg-[#0d0d0d] relative overflow-hidden">
            {/* Background decoration */}
            <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-blue-500/10 rounded-full blur-[120px]"></div>
            <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-indigo-500/10 rounded-full blur-[120px]"></div>

            <div className="w-full max-w-md p-8 glass-panel rounded-3xl border border-white/10 shadow-2xl relative z-10 m-4">
                <div className="flex flex-col items-center mb-10">
                    <div className="p-4 bg-indigo-500/20 rounded-2xl mb-4 border border-indigo-500/20 shadow-[0_0_20px_rgba(99,102,241,0.2)]">
                        <Shield className="text-indigo-400" size={40} />
                    </div>
                    <h1 className="text-3xl font-black text-white tracking-tight">Access Portal</h1>
                    <p className="text-slate-500 text-sm mt-2">Enter your operator credentials</p>
                </div>

                <form onSubmit={handleSubmit} className="space-y-6">
                    <div className="space-y-2">
                        <label className="text-xs font-bold text-slate-400 uppercase tracking-widest ml-1">Username</label>
                        <div className="relative">
                            <User className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                            <input
                                type="text"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                autoComplete="username"
                                className="w-full bg-slate-900/50 border border-slate-800 rounded-xl py-4 pl-12 pr-4 focus:ring-2 focus:ring-indigo-500 outline-none transition-all text-white placeholder:text-slate-600"
                                placeholder="ID-7728-OP"
                                required
                            />
                        </div>
                    </div>

                    <div className="space-y-2">
                        <label className="text-xs font-bold text-slate-400 uppercase tracking-widest ml-1">Password</label>
                        <div className="relative">
                            <Lock className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
                            <input
                                type="password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                autoComplete="current-password"
                                className="w-full bg-slate-900/50 border border-slate-800 rounded-xl py-4 pl-12 pr-4 focus:ring-2 focus:ring-indigo-500 outline-none transition-all text-white placeholder:text-slate-600"
                                placeholder="••••••••"
                                required
                            />
                        </div>
                    </div>

                    {error && <p className="text-red-400 text-xs font-bold text-center bg-red-400/10 py-3 rounded-lg border border-red-400/20 animate-shake">{error}</p>}

                    <button
                        type="submit"
                        disabled={isLoading}
                        className="w-full bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-800 text-white font-black py-4 rounded-xl transition-all shadow-xl shadow-indigo-600/20 flex items-center justify-center gap-2 group"
                    >
                        {isLoading ? <Loader2 className="animate-spin" size={20} /> : (
                            <>
                                Initialize Session
                                <ArrowRight size={20} className="group-hover:translate-x-1 transition-transform" />
                            </>
                        )}
                    </button>
                </form>

                <div className="mt-8 pt-8 border-t border-white/5 text-center">
                    <button
                        onClick={onToggle}
                        className="text-slate-500 hover:text-indigo-400 text-xs font-bold transition-colors"
                    >
                        Need a new account? Request access
                    </button>
                </div>
            </div>
        </div>
    );
};
