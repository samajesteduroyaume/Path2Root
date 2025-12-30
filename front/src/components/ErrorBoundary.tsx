import { Component, type ErrorInfo, type ReactNode } from 'react';
import { ShieldAlert, RefreshCw } from 'lucide-react';

interface Props {
    children?: ReactNode;
}

interface State {
    hasError: boolean;
    error: Error | null;
    errorInfo: ErrorInfo | null;
}

class ErrorBoundary extends Component<Props, State> {
    public state: State = {
        hasError: false,
        error: null,
        errorInfo: null
    };

    public static getDerivedStateFromError(error: Error): State {
        return { hasError: true, error, errorInfo: null };
    }

    public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
        console.error('Uncaught error:', error, errorInfo);
        this.setState({ error, errorInfo });
    }

    public render() {
        if (this.state.hasError) {
            return (
                <div className="min-h-screen bg-[#0d0d0d] flex items-center justify-center p-6 text-center">
                    <div className="glass-panel p-10 rounded-3xl border border-red-500/20 max-w-2xl space-y-6">
                        <div className="w-20 h-20 bg-red-500/10 rounded-2xl flex items-center justify-center mx-auto text-red-500 shadow-[0_0_30px_rgba(239,68,68,0.2)]">
                            <ShieldAlert size={48} />
                        </div>
                        <div className="space-y-2">
                            <h1 className="text-2xl font-black text-white">Interface interrompue</h1>
                            <p className="text-slate-500 text-sm">Une exception de rendu s'est produite. Vos données ont été conservées dans la session.</p>
                        </div>

                        {/* Error Details */}
                        {this.state.error && (
                            <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-4 text-left">
                                <div className="text-xs font-bold text-red-400 mb-2">Détails de l'erreur :</div>
                                <div className="text-xs font-mono text-slate-400 mb-2">{this.state.error.toString()}</div>
                                {this.state.errorInfo && (
                                    <details className="mt-2">
                                        <summary className="text-xs text-slate-500 cursor-pointer hover:text-slate-400">Stack trace</summary>
                                        <pre className="text-[10px] text-slate-600 mt-2 overflow-auto max-h-40">
                                            {this.state.errorInfo.componentStack}
                                        </pre>
                                    </details>
                                )}
                            </div>
                        )}

                        <button
                            onClick={() => window.location.reload()}
                            className="w-full bg-slate-800 hover:bg-slate-700 text-white font-bold py-4 rounded-xl transition-all border border-slate-700 flex items-center justify-center gap-2"
                        >
                            <RefreshCw size={18} /> Réinitialiser l'interface
                        </button>
                    </div>
                </div>
            );
        }

        return this.props.children;
    }
}

export default ErrorBoundary;
