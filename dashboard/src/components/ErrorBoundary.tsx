import { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error in NetSight component tree:', error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#F6F5F1] text-[#16181D] flex items-center justify-center p-6">
          <div className="max-w-md w-full bg-white border border-[#E2E0D8] rounded-md p-6 shadow-sm">
            <div className="flex items-center gap-3 text-[#C2410C] mb-4">
              <AlertTriangle className="w-6 h-6 flex-shrink-0" />
              <h2 className="text-lg font-semibold">Something went wrong</h2>
            </div>
            <p className="text-sm text-[#4B515B] mb-4">
              An unexpected error occurred in the NetSight interface:
            </p>
            <div className="p-3 bg-[#F6F5F1] rounded border border-[#E2E0D8] font-mono text-xs text-[#16181D] mb-6 overflow-x-auto">
              {this.state.error?.message || 'Unknown render error'}
            </div>
            <button
              onClick={() => window.location.reload()}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 bg-[#2347C5] hover:bg-[#1b38a0] text-white text-sm font-medium rounded transition-colors"
            >
              <RefreshCw className="w-4 h-4" />
              Reload Application
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
