import React, { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Terminal as TerminalIcon, ChevronRight, CheckCircle2, AlertTriangle, XCircle, Info, Clock, Maximize2, Minimize2 } from 'lucide-react';

interface LogEntry {
    id: string;
    text: string;
    timestamp: number;
    type: 'command' | 'output' | 'success' | 'error' | 'info' | 'warning';
}

interface CommandTerminalProps {
    logs: LogEntry[];
    onCommand?: (cmd: string) => void;
}

export const CommandTerminal: React.FC<CommandTerminalProps> = ({ logs, onCommand }) => {
    const terminalRef = useRef<HTMLDivElement>(null);
    const inputRef = useRef<HTMLInputElement>(null);
    const [isMaximized, setIsMaximized] = useState(false);
    const [inputValue, setInputValue] = useState('');

    useEffect(() => {
        if (terminalRef.current) {
            terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
        }
    }, [logs]);

    const getLogStyles = (type: LogEntry['type']) => {
        switch (type) {
            case 'command':
                return {
                    text: 'text-indigo-400',
                    bg: 'bg-indigo-500/5',
                    border: 'border-indigo-500/20',
                    icon: <ChevronRight size={14} className="text-indigo-500" />,
                };
            case 'success':
                return {
                    text: 'text-emerald-400',
                    bg: 'bg-emerald-500/5',
                    border: 'border-emerald-500/20',
                    icon: <CheckCircle2 size={14} className="text-emerald-500" />,
                };
            case 'error':
                return {
                    text: 'text-rose-400',
                    bg: 'bg-rose-500/5',
                    border: 'border-rose-500/20',
                    icon: <XCircle size={14} className="text-rose-500" />,
                };
            case 'warning':
                return {
                    text: 'text-amber-400',
                    bg: 'bg-amber-500/5',
                    border: 'border-amber-500/20',
                    icon: <AlertTriangle size={14} className="text-amber-500" />,
                };
            case 'info':
                return {
                    text: 'text-sky-400',
                    bg: 'bg-sky-500/5',
                    border: 'border-sky-500/20',
                    icon: <Info size={14} className="text-sky-500" />,
                };
            default:
                return {
                    text: 'text-slate-300',
                    bg: 'bg-white/5',
                    border: 'border-white/10',
                    icon: <ChevronRight size={14} className="text-slate-500" />,
                };
        }
    };

    const toggleMaximized = () => {
        setIsMaximized(!isMaximized);
    };

    useEffect(() => {
        const handleKeyDown = (e: KeyboardEvent) => {
            if (e.key === 'Escape' && isMaximized) {
                setIsMaximized(false);
            }
        };
        window.addEventListener('keydown', handleKeyDown);
        return () => window.removeEventListener('keydown', handleKeyDown);
    }, [isMaximized]);

    const handleInputSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (!inputValue.trim()) return;

        if (onCommand) {
            onCommand(inputValue.trim());
        }
        setInputValue('');
    };

    const TerminalContent = (
        <div className={`
            flex flex-col bg-[#0a0a0b] border border-white/10 overflow-hidden shadow-2xl relative group transition-all duration-300
            ${isMaximized
                ? 'fixed inset-4 z-[9999] rounded-3xl h-[calc(100vh-2rem)]'
                : 'h-full min-h-[300px] max-h-[500px] w-full rounded-2xl'}
        `}>
            {/* Scanline Effect Overlay */}
            <div className="absolute inset-0 pointer-events-none z-20 opacity-[0.03] bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[length:100%_2px,3px_100%]"></div>

            {/* Header */}
            <div className="flex items-center gap-3 px-5 py-3 bg-white/5 border-b border-white/10 backdrop-blur-md z-10">
                <div className="flex gap-1.5 items-center">
                    <TerminalIcon size={14} className="text-indigo-400" />
                    <span className="text-[10px] font-black tracking-wider uppercase text-indigo-300">Tactical Node</span>
                </div>
                <div className="ml-auto flex items-center gap-4">
                    <button
                        onClick={toggleMaximized}
                        className="p-1.5 hover:bg-white/10 rounded-lg border border-white/5 transition-all text-slate-400 hover:text-white flex items-center gap-2 group/btn"
                        title={isMaximized ? "Restore (ESC)" : "Maximize"}
                    >
                        <span className="text-[9px] font-bold uppercase opacity-0 group-hover/btn:opacity-100 transition-opacity">
                            {isMaximized ? "Restore" : "Full Screen"}
                        </span>
                        {isMaximized ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
                    </button>
                    <div className="flex items-center gap-2 px-2 py-0.5 bg-emerald-500/10 rounded-md border border-emerald-500/20">
                        <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></div>
                        <span className="text-[10px] font-bold text-emerald-500/70 uppercase tracking-tighter tabular-nums">
                            {logs.length.toString().padStart(3, '0')} LOGS
                        </span>
                    </div>
                </div>
            </div>

            {/* Logs Area */}
            <div
                ref={terminalRef}
                className="flex-1 overflow-y-auto p-4 font-mono text-[11px] leading-relaxed custom-scrollbar selection:bg-indigo-500/30"
            >
                {logs.length === 0 ? (
                    <div className="h-full flex flex-col items-center justify-center opacity-20">
                        <TerminalIcon size={48} className="text-slate-500 mb-4" />
                        <p className="text-slate-500 font-bold uppercase tracking-[0.2em]">Awaiting system initialization...</p>
                    </div>
                ) : (
                    <div className="space-y-1">
                        {logs.map((log, index) => {
                            const styles = getLogStyles(log.type);
                            return (
                                <div key={log.id} className="group/item flex flex-col terminal-entry-animate">
                                    <div className={`p-1.5 rounded-lg border transition-all duration-300 ${styles.bg} ${styles.border} group-hover/item:border-white/20`}>
                                        <div className="flex items-start gap-3">
                                            <div className="mt-0.5 opacity-60 group-hover/item:opacity-100 transition-opacity">
                                                {styles.icon}
                                            </div>
                                            <div className="flex-1">
                                                <div className="flex items-center gap-2 mb-1">
                                                    <span className="text-[9px] font-bold text-slate-500 tabular-nums flex items-center gap-1">
                                                        <Clock size={10} />
                                                        {new Date(log.timestamp).toLocaleTimeString([], { hour12: false })}
                                                    </span>
                                                    <span className={`text-[8px] font-black uppercase px-1.5 py-0.5 rounded bg-white/5 border border-white/5 ${styles.text}`}>
                                                        {log.type}
                                                    </span>
                                                    <div className="h-px flex-1 bg-white/5"></div>
                                                </div>
                                                <div className={`${styles.text} whitespace-pre-wrap break-all leading-normal`}>
                                                    {log.text}
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    {index < logs.length - 1 && <div className="h-1 w-px bg-white/5 ml-5"></div>}
                                </div>
                            );
                        })}
                    </div>
                )}
            </div>

            {/* Footer / Command Input */}
            <form
                onSubmit={handleInputSubmit}
                className="px-5 py-2 bg-indigo-500/5 border-t border-white/5 flex items-center gap-2 group/input focus-within:bg-indigo-500/10 transition-colors"
                onClick={() => inputRef.current?.focus()}
            >
                <span className="text-indigo-400 font-bold font-mono text-[10px] tracking-tight shrink-0">OPERATOR@PATH2ROOT:~$</span>
                <input
                    ref={inputRef}
                    type="text"
                    value={inputValue}
                    onChange={(e) => setInputValue(e.target.value)}
                    className="flex-1 bg-transparent border-none outline-none text-indigo-300 font-mono text-[11px] placeholder:text-indigo-500/30"
                    placeholder="ENTER COMMAND (HELP, CLEAR, SCAN...)"
                    spellCheck={false}
                    autoComplete="off"
                />
                <div className="w-1.5 h-3.5 bg-indigo-500/50 animate-pulse shrink-0"></div>
            </form>
        </div>
    );

    if (isMaximized) {
        return createPortal(
            <div className="fixed inset-0 z-[9999] bg-black/80 backdrop-blur-md flex items-center justify-center p-4 overflow-hidden">
                {TerminalContent}
            </div>,
            document.body
        );
    }

    return TerminalContent;
};
