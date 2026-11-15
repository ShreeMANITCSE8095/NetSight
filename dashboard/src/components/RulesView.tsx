import React, { useState } from 'react';
import { Plus, Trash2, Shield, AlertCircle } from 'lucide-react';

export interface FirewallRules {
  block_apps?: string[];
  block_ips: string[];
  block_domains: string[];
  block_ports: number[];
}

interface RulesViewProps {
  rules: FirewallRules;
  onAddRule: (type: 'ip' | 'domain' | 'port', value: string) => Promise<void>;
  onRemoveRule: (type: 'ip' | 'domain' | 'port', value: string | number) => Promise<void>;
}

export const RulesView: React.FC<RulesViewProps> = ({
  rules,
  onAddRule,
  onRemoveRule,
}) => {
  const [ipInput, setIpInput] = useState('');
  const [domainInput, setDomainInput] = useState('');
  const [portInput, setPortInput] = useState('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleAdd = async (
    type: 'ip' | 'domain' | 'port',
    value: string,
    clearFn: () => void
  ) => {
    setErrorMsg(null);
    try {
      await onAddRule(type, value);
      clearFn();
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to add rule');
    }
  };

  const sections = [
    {
      type: 'ip' as const,
      title: 'Blocked IP Addresses',
      subtitle: 'Drop packets matching source or destination IPv4',
      placeholder: 'e.g. 192.168.1.50',
      input: ipInput,
      setInput: setIpInput,
      items: rules.block_ips,
    },
    {
      type: 'domain' as const,
      title: 'Blocked TLS SNI / DNS Domains',
      subtitle: 'Filter flows matching extracted hostname',
      placeholder: 'e.g. ads.example.com',
      input: domainInput,
      setInput: setDomainInput,
      items: rules.block_domains,
    },
    {
      type: 'port' as const,
      title: 'Blocked TCP/UDP Ports',
      subtitle: 'Drop traffic on restricted transport ports',
      placeholder: 'e.g. 4444',
      input: portInput,
      setInput: setPortInput,
      items: rules.block_ports,
    },
  ];

  return (
    <div className="flex flex-col gap-4">
      {errorMsg && (
        <div className="flex items-center gap-2 p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-xs text-rose-500">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {sections.map((sec) => (
          <div
            key={sec.type}
            className="rounded-xl bg-surface border border-subtle p-5 flex flex-col justify-between min-h-[320px]"
          >
            <div>
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-primary">{sec.title}</h3>
                <Shield className="w-4 h-4 text-[#4F46E5]" />
              </div>
              <p className="text-xs text-secondary mt-0.5 mb-4">{sec.subtitle}</p>

              <form
                onSubmit={async (e) => {
                  e.preventDefault();
                  if (!sec.input.trim()) return;
                  await handleAdd(sec.type, sec.input.trim(), () => sec.setInput(''));
                }}
                className="flex gap-2 mb-4"
              >
                <input
                  type="text"
                  value={sec.input}
                  onChange={(e) => sec.setInput(e.target.value)}
                  placeholder={sec.placeholder}
                  className="flex-1 h-8 px-3 rounded-lg bg-canvas border border-subtle text-xs font-mono text-primary placeholder:text-secondary focus:outline-none focus:border-[#4F46E5]"
                />
                <button
                  type="submit"
                  className="h-8 px-3 rounded-lg bg-[#4F46E5] hover:bg-[#4338CA] text-white text-xs font-medium inline-flex items-center gap-1 transition-colors"
                >
                  <Plus className="w-3.5 h-3.5" /> Add
                </button>
              </form>

              <div className="flex flex-col gap-1.5 max-h-56 overflow-y-auto">
                {sec.items.length === 0 ? (
                  <div className="py-8 text-center text-xs text-secondary">
                    No active rules.
                  </div>
                ) : (
                  sec.items.map((item) => (
                    <div
                      key={String(item)}
                      className="flex items-center justify-between px-3 py-1.5 rounded-lg bg-canvas border border-subtle text-xs font-mono"
                    >
                      <span className="text-primary">{String(item)}</span>
                      <button
                        onClick={async () => {
                          try {
                            await onRemoveRule(sec.type, item);
                          } catch (err: any) {
                            setErrorMsg(err.message || 'Failed to remove rule');
                          }
                        }}
                        className="text-secondary hover:text-rose-500 transition-colors"
                        title="Remove rule"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
